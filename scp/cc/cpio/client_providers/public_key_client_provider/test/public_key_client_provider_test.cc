// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "cpio/client_providers/public_key_client_provider/src/public_key_client_provider.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <string>

#include "absl/synchronization/blocking_counter.h"
#include "absl/synchronization/notification.h"
#include "core/http2_client/mock/mock_http_client.h"
#include "core/interface/async_context.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"
#include "public/cpio/proto/public_key_service/v1/public_key_service.pb.h"

using google::cmrt::sdk::public_key_service::v1::ListPublicKeysRequest;
using google::cmrt::sdk::public_key_service::v1::ListPublicKeysResponse;
using google::protobuf::Any;
using google::scp::core::AsyncContext;
using google::scp::core::BytesBuffer;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpHeaders;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::Uri;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::
    SC_PUBLIC_KEY_CLIENT_PROVIDER_ALL_URIS_REQUEST_PERFORM_FAILED;
using google::scp::core::errors::
    SC_PUBLIC_KEY_CLIENT_PROVIDER_HTTP_CLIENT_REQUIRED;
using google::scp::core::errors::
    SC_PUBLIC_KEY_CLIENT_PROVIDER_INVALID_CONFIG_OPTIONS;
using google::scp::core::http2_client::mock::MockHttpClient;
using google::scp::core::test::ResultIs;
using ::testing::StrEq;

static constexpr char kPublicKeyHeaderDate[] = "date";
static constexpr char kPublicKeyHeaderCacheControl[] = "cache-control";
static constexpr char kPrivateKeyBaseUri1[] = "http://public_key/publicKeys1";
static constexpr char kPrivateKeyBaseUri2[] = "http://public_key/publicKeys2";
static constexpr char kHeaderDateExample[] = "Wed, 16 Nov 2022 00:02:48 GMT";
static constexpr char kCacheControlExample[] = "max-age=254838";
static constexpr uint64_t kExpectedExpiredTimeInSeconds = 1668811806;

namespace google::scp::cpio::client_providers::test {

TEST(PublicKeyClientProviderTestI, InitFailedWithInvalidConfig) {
  auto http_client = std::make_shared<MockHttpClient>();

  auto public_key_client_options = std::make_shared<PublicKeyClientOptions>();

  auto public_key_client = std::make_unique<PublicKeyClientProvider>(
      public_key_client_options, http_client);

  EXPECT_THAT(public_key_client->Init(),
              ResultIs(FailureExecutionResult(
                  SC_PUBLIC_KEY_CLIENT_PROVIDER_INVALID_CONFIG_OPTIONS)));
}

TEST(PublicKeyClientProviderTestI, InitFailedInvalidHttpClient) {
  auto public_key_client_options = std::make_shared<PublicKeyClientOptions>();
  public_key_client_options->endpoints.emplace_back(kPrivateKeyBaseUri1);

  auto public_key_client = std::make_unique<PublicKeyClientProvider>(
      public_key_client_options, nullptr);

  EXPECT_THAT(public_key_client->Init(),
              ResultIs(FailureExecutionResult(
                  SC_PUBLIC_KEY_CLIENT_PROVIDER_HTTP_CLIENT_REQUIRED)));
}

class PublicKeyClientProviderTestII : public ::testing::Test {
 protected:
  void SetUp() override {
    http_client_ = std::make_shared<MockHttpClient>();

    auto public_key_client_options = std::make_shared<PublicKeyClientOptions>();
    public_key_client_options->endpoints.emplace_back(kPrivateKeyBaseUri1);
    public_key_client_options->endpoints.emplace_back(kPrivateKeyBaseUri2);

    public_key_client_ = std::make_unique<PublicKeyClientProvider>(
        public_key_client_options, http_client_);

    EXPECT_SUCCESS(public_key_client_->Init());
    EXPECT_SUCCESS(public_key_client_->Run());
  }

  HttpResponse GetValidHttpResponse() {
    HttpResponse response;
    HttpHeaders headers;
    headers.insert({kPublicKeyHeaderDate, kHeaderDateExample});
    headers.insert({kPublicKeyHeaderCacheControl, kCacheControlExample});
    response.headers = std::make_shared<HttpHeaders>(headers);

    std::string bytes_str = R"({
      "keys": [
        {"id": "1234", "key": "abcdefg"},
        {"id": "5678", "key": "hijklmn"}
    ]})";

    BytesBuffer bytes(bytes_str.length());

    response.body.bytes->assign(bytes_str.begin(), bytes_str.end());
    response.body.length = bytes_str.length();
    return response;
  }

  void TearDown() override {
    if (public_key_client_) {
      EXPECT_SUCCESS(public_key_client_->Stop());
    }
  }

  std::shared_ptr<MockHttpClient> http_client_;
  std::unique_ptr<PublicKeyClientProvider> public_key_client_;
};

TEST_F(PublicKeyClientProviderTestII, ListPublicKeysSuccess) {
  absl::BlockingCounter perform_calls(2);
  auto success_response = GetValidHttpResponse();
  http_client_->perform_request_mock =
      [&](AsyncContext<HttpRequest, HttpResponse>& http_context) {
        perform_calls.DecrementCount();
        http_context.response =
            std::make_shared<HttpResponse>(success_response);
        http_context.result = SuccessExecutionResult();
        http_context.Finish();
        return SuccessExecutionResult();
      };

  auto request = std::make_shared<ListPublicKeysRequest>();

  absl::Notification success_callback;
  AsyncContext<ListPublicKeysRequest, ListPublicKeysResponse> context(
      std::move(request), [&](AsyncContext<ListPublicKeysRequest,
                                           ListPublicKeysResponse>& context) {
        ASSERT_SUCCESS(context.result);
        EXPECT_THAT(context.response->public_keys()[0].key_id(), StrEq("1234"));
        EXPECT_THAT(context.response->public_keys()[0].public_key(),
                    StrEq("abcdefg"));
        EXPECT_THAT(context.response->public_keys()[1].key_id(), StrEq("5678"));
        EXPECT_THAT(context.response->public_keys()[1].public_key(),
                    StrEq("hijklmn"));
        EXPECT_EQ(context.response->expiration_time().seconds(),
                  kExpectedExpiredTimeInSeconds);
        success_callback.Notify();
      });

  EXPECT_SUCCESS(public_key_client_->ListPublicKeys(context));
  // ListPublicKeys context callback will only run once even all uri get
  // success.
  success_callback.WaitForNotification();
  // Http client PerformRequest() has being called twice. All uris in
  // public_key_client_options will being called.
  perform_calls.Wait();
}

TEST_F(PublicKeyClientProviderTestII, ListPublicKeysFailure) {
  ExecutionResult failed_result = FailureExecutionResult(SC_UNKNOWN);

  absl::BlockingCounter perform_calls(2);
  auto success_response = GetValidHttpResponse();
  http_client_->perform_request_mock =
      [&](AsyncContext<HttpRequest, HttpResponse>& http_context) {
        perform_calls.DecrementCount();

        http_context.result = failed_result;
        http_context.Finish();
        return SuccessExecutionResult();
      };

  auto request = std::make_shared<ListPublicKeysRequest>();

  absl::Notification failure_callback;
  AsyncContext<ListPublicKeysRequest, ListPublicKeysResponse> context(
      std::move(request), [&](AsyncContext<ListPublicKeysRequest,
                                           ListPublicKeysResponse>& context) {
        EXPECT_THAT(context.result,
                    ResultIs(FailureExecutionResult(SC_UNKNOWN)));
        failure_callback.Notify();
      });

  EXPECT_SUCCESS(public_key_client_->ListPublicKeys(context));

  // ListPublicKeys context callback will only run once even all uri get
  // fail.
  failure_callback.WaitForNotification();
  perform_calls.Wait();
}

TEST_F(PublicKeyClientProviderTestII, AllUrisPerformRequestFailed) {
  absl::BlockingCounter perform_calls(2);
  auto success_response = GetValidHttpResponse();
  http_client_->perform_request_mock =
      [&](AsyncContext<HttpRequest, HttpResponse>& http_context) {
        perform_calls.DecrementCount();
        return FailureExecutionResult(SC_UNKNOWN);
      };

  auto request = std::make_shared<ListPublicKeysRequest>();

  auto cpio_failure = FailureExecutionResult(
      SC_PUBLIC_KEY_CLIENT_PROVIDER_ALL_URIS_REQUEST_PERFORM_FAILED);

  absl::Notification failure_callback;
  AsyncContext<ListPublicKeysRequest, ListPublicKeysResponse> context(
      std::move(request), [&](AsyncContext<ListPublicKeysRequest,
                                           ListPublicKeysResponse>& context) {
        EXPECT_THAT(context.result, ResultIs(cpio_failure));
        failure_callback.Notify();
      });

  EXPECT_THAT(public_key_client_->ListPublicKeys(context),
              ResultIs(cpio_failure));

  // ListPublicKeys context callback will only run once even all uri get
  // fail.
  failure_callback.WaitForNotification();
  perform_calls.Wait();
}

TEST_F(PublicKeyClientProviderTestII, ListPublicKeysPartialUriSuccess) {
  ExecutionResult failed_result = FailureExecutionResult(SC_UNKNOWN);
  absl::BlockingCounter perform_calls(2);
  auto success_response = GetValidHttpResponse();
  http_client_->perform_request_mock =
      [&](AsyncContext<HttpRequest, HttpResponse>& http_context) {
        perform_calls.DecrementCount();
        if (*http_context.request->path == kPrivateKeyBaseUri2) {
          http_context.response =
              std::make_shared<HttpResponse>(success_response);
          http_context.result = SuccessExecutionResult();
          http_context.Finish();
          return SuccessExecutionResult();
        }

        http_context.result = failed_result;
        http_context.Finish();

        return failed_result;
      };

  auto request = std::make_shared<ListPublicKeysRequest>();
  absl::Notification success_callback;
  AsyncContext<ListPublicKeysRequest, ListPublicKeysResponse> context(
      std::move(request), [&](AsyncContext<ListPublicKeysRequest,
                                           ListPublicKeysResponse>& context) {
        EXPECT_SUCCESS(context.result);
        success_callback.Notify();
      });

  EXPECT_SUCCESS(public_key_client_->ListPublicKeys(context));
  // ListPublicKeys success with partial uris got success response.
  success_callback.WaitForNotification();
  perform_calls.Wait();
}

}  // namespace google::scp::cpio::client_providers::test
