// Portions Copyright (c) Microsoft Corporation
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

#include "cpio/client_providers/auth_token_provider/src/azure/azure_auth_token_provider.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "core/curl_client/mock/mock_curl_client.h"
#include "cpio/client_providers/auth_token_provider/src/azure/error_codes.h"
#include "public/core/test/interface/execution_result_matchers.h"

using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::BytesBuffer;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpClientInterface;
using google::scp::core::HttpHeaders;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::RetryExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::Uri;
using google::scp::core::errors::
    SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_BAD_SESSION_TOKEN;
using google::scp::core::errors::
    SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_INITIALIZATION_FAILED;
using google::scp::core::test::IsSuccessful;
using google::scp::core::test::MockCurlClient;
using google::scp::core::test::ResultIs;
using testing::Contains;
using testing::EndsWith;
using testing::Eq;
using testing::IsNull;
using testing::Pair;
using testing::Pointee;
using testing::UnorderedElementsAre;

namespace {
constexpr char kTokenServerPath[] = "http://169.254.169.254/metadata/identity/oauth2/"
    "token?api-version=2018-02-01";
constexpr char kMetadataHeader[] = "Metadata";
constexpr char kMetadataHeaderValue[] = "true";
constexpr int kTokenTtlInSecondHeaderValue = 1000;
constexpr int kExtendedTokenTtlInSecondHeaderValue = 1000;
constexpr char kTokenPayloadValue[] = "b0Aaekm1IeizWZVKoBQQULOiiT_PDcQk";
const std::string kHttpResponseMock =
    std::string(R"({
      "access_token":")") + kTokenPayloadValue + R"(",
      "expires_in":)" + std::to_string(kTokenTtlInSecondHeaderValue) + R"(,
      "ext_expires_in": )" + std::to_string(kExtendedTokenTtlInSecondHeaderValue) + R"(,
      "token_type":"bearer"
    })";
}  // namespace

namespace google::scp::cpio::client_providers::test {

class AzureAuthTokenProviderTest : public testing::TestWithParam<std::string> {
 protected:
  AzureAuthTokenProviderTest()
      : http_client_(std::make_shared<MockCurlClient>()),
        authorizer_provider_(
            std::make_unique<AzureAuthTokenProvider>(http_client_)) {}

  std::string GetResponseBody() { return GetParam(); }

  AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>
      fetch_token_context_;

  std::shared_ptr<MockCurlClient> http_client_;
  std::unique_ptr<AzureAuthTokenProvider> authorizer_provider_;
};

TEST_F(AzureAuthTokenProviderTest,
       GetSessionTokenSuccessWithValidTokenAndExpireTime) {
  EXPECT_CALL(*http_client_, PerformRequest).WillOnce([](auto& http_context) {
    http_context.result = SuccessExecutionResult();
    EXPECT_EQ(http_context.request->method, HttpMethod::GET);
    EXPECT_THAT(http_context.request->path, Pointee(Eq(kTokenServerPath)));
    EXPECT_THAT(http_context.request->headers,
                Pointee(UnorderedElementsAre(
                    Pair(kMetadataHeader,
                         kMetadataHeaderValue))));

    http_context.response = std::make_shared<HttpResponse>();
    http_context.response->body = BytesBuffer(kHttpResponseMock);
    http_context.Finish();
    return SuccessExecutionResult();
  });

  absl::Notification finished;
  fetch_token_context_.callback = [&finished](auto& context) {
    ASSERT_SUCCESS(context.result);
    ASSERT_TRUE(context.response);
    EXPECT_THAT(context.response->session_token,
                Pointee(Eq(kTokenPayloadValue)));
    EXPECT_EQ(context.response->token_lifetime_in_seconds,
              std::chrono::seconds(kTokenTtlInSecondHeaderValue));
    finished.Notify();
  };
  EXPECT_THAT(authorizer_provider_->GetSessionToken(fetch_token_context_),
              IsSuccessful());

  finished.WaitForNotification();
}

TEST_F(AzureAuthTokenProviderTest, GetSessionTokenFailsIfHttpRequestFails) {
  EXPECT_CALL(*http_client_, PerformRequest).WillOnce([](auto& http_context) {
    http_context.result = FailureExecutionResult(SC_UNKNOWN);
    http_context.Finish();
    return SuccessExecutionResult();
  });

  absl::Notification finished;
  fetch_token_context_.callback = [&finished](auto& context) {
    EXPECT_THAT(context.result, ResultIs(FailureExecutionResult(SC_UNKNOWN)));
    finished.Notify();
  };
  EXPECT_THAT(authorizer_provider_->GetSessionToken(fetch_token_context_),
              IsSuccessful());

  finished.WaitForNotification();
}

TEST_F(AzureAuthTokenProviderTest, NullHttpClientProvider) {
  auto auth_token_provider = std::make_shared<AzureAuthTokenProvider>(nullptr);

  EXPECT_THAT(auth_token_provider->Init(),
              ResultIs(FailureExecutionResult(
                  SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_INITIALIZATION_FAILED)));
}
}  // namespace google::scp::cpio::client_providers::test
