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
using std::atomic;
using std::atomic_bool;
using std::bind;
using std::dynamic_pointer_cast;
using std::thread;
using std::chrono::seconds;
using testing::Contains;
using testing::EndsWith;
using testing::Eq;
using testing::IsNull;
using testing::Pair;
using testing::Pointee;
using testing::UnorderedElementsAre;

namespace {
constexpr char kTokenServerPath[] =
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token";
constexpr char kMetadataFlavorHeader[] = "Metadata-Flavor";
constexpr char kMetadataFlavorHeaderValue[] = "Google";
constexpr char kHttpResponseMock[] =
    R"({
      "access_token":"b0Aaekm1IeizWZVKoBQQULOiiT_PDcQk",
      "expires_in":3599,
      "token_type":"Bearer"
    })";
constexpr char kAccessTokenMock[] = "b0Aaekm1IeizWZVKoBQQULOiiT_PDcQk";
constexpr seconds kTokenLifetime = seconds(3599);

constexpr char kAuthorizationHeaderKey[] = "Authorization";
constexpr char kBearerTokenPrefix[] = "Bearer ";
constexpr char kHttpRequestUriForSigning[] = "www.test.com ";

constexpr char kIdentityServerPath[] =
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/"
    "identity";
constexpr char kAudience[] = "www.google.com";
constexpr seconds kTokenLifetimeForTargetAudience = seconds(3600);

// eyJleHAiOjE2NzI3NjA3MDEsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwic3ViIjoic3ViamVjdCIsImlhdCI6MTY3Mjc1NzEwMX0=
// decodes to:
// "{"exp":1672760701,"iss":"issuer","aud":"audience","sub":"subject","iat":1672757101}"
constexpr char kBase64EncodedResponse[] =
    "someheader."
    "eyJleHAiOjE2NzI3NjA3MDEsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwic3ViIj"
    "oic3ViamVjdCIsImlhdCI6MTY3Mjc1NzEwMX0=.signature";
}  // namespace

namespace google::scp::cpio::client_providers::test {

class AadAuthTokenProviderTest : public testing::TestWithParam<std::string> {
 protected:
  AadAuthTokenProviderTest()
      : http_client_(std::make_shared<MockCurlClient>()) {
    authorizer_provider_ = std::make_unique<AadAuthTokenProvider>(http_client_);
    fetch_token_for_target_audience_context_.request =
        std::make_shared<GetSessionTokenForTargetAudienceRequest>();
    fetch_token_for_target_audience_context_.request
        ->token_target_audience_uri = std::make_shared<std::string>(kAudience);
  }

  std::string GetResponseBody() { return GetParam(); }

  AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>
      fetch_token_context_;
  AsyncContext<HttpRequest, HttpRequest> sign_http_request_context_;

  AsyncContext<GetSessionTokenForTargetAudienceRequest, GetSessionTokenResponse>
      fetch_token_for_target_audience_context_;

  std::shared_ptr<MockCurlClient> http_client_;
  std::unique_ptr<AadAuthTokenProvider> authorizer_provider_;
};

TEST_F(AadAuthTokenProviderTest,
       GetSessionTokenSuccessWithValidTokenAndExpireTime) {
  EXPECT_CALL(*http_client_, PerformRequest).WillOnce([](auto& http_context) {
    http_context.result = SuccessExecutionResult();
    EXPECT_EQ(http_context.request->method, HttpMethod::GET);
    EXPECT_THAT(http_context.request->path, Pointee(Eq(kTokenServerPath)));
    EXPECT_THAT(http_context.request->headers,
                Pointee(UnorderedElementsAre(
                    Pair(kMetadataFlavorHeader, kMetadataFlavorHeaderValue))));

    http_context.response = std::make_shared<HttpResponse>();
    http_context.response->body = BytesBuffer(kHttpResponseMock);
    http_context.Finish();
    return SuccessExecutionResult();
  });

  absl::Notification finished;
  fetch_token_context_.callback = [&finished](auto& context) {
    EXPECT_SUCCESS(context.result);
    if (!context.response) {
      ADD_FAILURE();
    } else {
      EXPECT_THAT(context.response->session_token,
                  Pointee(Eq(kAccessTokenMock)));
      EXPECT_EQ(context.response->token_lifetime_in_seconds, kTokenLifetime);
    }
    finished.Notify();
  };
  EXPECT_THAT(authorizer_provider_->GetSessionToken(fetch_token_context_),
              IsSuccessful());

  finished.WaitForNotification();
}

TEST_F(AadAuthTokenProviderTest, GetSessionTokenFailsIfHttpRequestFails) {
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

TEST_P(AadAuthTokenProviderTest, GetSessionTokenFailsIfBadJson) {
  EXPECT_CALL(*http_client_, PerformRequest)
      .WillOnce([this](auto& http_context) {
        http_context.result = SuccessExecutionResult();
        http_context.response = std::make_shared<HttpResponse>();
        http_context.response->body = BytesBuffer(GetResponseBody());
        http_context.Finish();
        return SuccessExecutionResult();
      });

  absl::Notification finished;
  fetch_token_context_.callback = [&finished](auto& context) {
    EXPECT_THAT(context.result,
                ResultIs(RetryExecutionResult(
                    SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_BAD_SESSION_TOKEN)));
    finished.Notify();
  };
  EXPECT_THAT(authorizer_provider_->GetSessionToken(fetch_token_context_),
              IsSuccessful());

  finished.WaitForNotification();
}

INSTANTIATE_TEST_SUITE_P(BadTokens, AadAuthTokenProviderTest,
                         testing::Values(
                             R"""({
                              "access_token": "INVALID-JSON",
                              "expires_in": 3599,
                              "token_type"
                            })""" /*invalid Json, token_type missing value*/,
                             R"""({
                              "access_token": "INVALID-JSON",
                              "token_type": "Bearer"
                            })""" /*missing field*/,
                             R"""({
                              "expires_in": 3599,
                              "token_type": "Bearer"
                            })""" /*missing field*/,
                             R"""({
                              "access_token": "INVALID-JSON",
                              "expires_in": 3599
                            })""" /*missing field*/));

TEST_F(AadAuthTokenProviderTest, NullHttpClientProvider) {
  auto auth_token_provider = std::make_shared<AadAuthTokenProvider>(nullptr);

  EXPECT_THAT(auth_token_provider->Init(),
              ResultIs(FailureExecutionResult(
                  SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_INITIALIZATION_FAILED)));
}

TEST_F(AadAuthTokenProviderTest, FetchTokenForTargetAudienceSuccessfully) {
  EXPECT_CALL(*http_client_, PerformRequest).WillOnce([](auto& http_context) {
    http_context.result = SuccessExecutionResult();
    EXPECT_EQ(http_context.request->method, HttpMethod::GET);
    EXPECT_THAT(http_context.request->path, Pointee(Eq(kIdentityServerPath)));
    EXPECT_THAT(http_context.request->query,
                Pointee(absl::StrCat("audience=", kAudience, "&format=full")));
    EXPECT_THAT(http_context.request->headers,
                Pointee(UnorderedElementsAre(
                    Pair(kMetadataFlavorHeader, kMetadataFlavorHeaderValue))));

    http_context.response = std::make_shared<HttpResponse>();
    http_context.response->body = BytesBuffer(kBase64EncodedResponse);
    http_context.Finish();
    return SuccessExecutionResult();
  });

  absl::Notification finished;
  fetch_token_for_target_audience_context_.callback =
      [&finished](auto& context) {
        EXPECT_SUCCESS(context.result);
        EXPECT_EQ(*context.response->session_token, kBase64EncodedResponse);
        EXPECT_EQ(context.response->token_lifetime_in_seconds,
                  kTokenLifetimeForTargetAudience);

        finished.Notify();
      };
  EXPECT_THAT(authorizer_provider_->GetSessionTokenForTargetAudience(
                  fetch_token_for_target_audience_context_),
              IsSuccessful());

  finished.WaitForNotification();
}

TEST_F(AadAuthTokenProviderTest,
       FetchTokenForTargetAudienceFailsIfHttpRequestFails) {
  EXPECT_CALL(*http_client_, PerformRequest).WillOnce([](auto& http_context) {
    http_context.result = FailureExecutionResult(SC_UNKNOWN);
    http_context.Finish();
    return SuccessExecutionResult();
  });

  absl::Notification finished;
  fetch_token_for_target_audience_context_.callback = [&finished](
                                                          auto& context) {
    EXPECT_THAT(context.result, ResultIs(FailureExecutionResult(SC_UNKNOWN)));
    finished.Notify();
  };
  EXPECT_THAT(authorizer_provider_->GetSessionTokenForTargetAudience(
                  fetch_token_for_target_audience_context_),
              IsSuccessful());

  finished.WaitForNotification();
}

TEST_P(AadAuthTokenProviderTest, FetchTokenForTargetAudienceFailsIfBadJson) {
  EXPECT_CALL(*http_client_, PerformRequest)
      .WillOnce([this](auto& http_context) {
        http_context.result = SuccessExecutionResult();

        http_context.response = std::make_shared<HttpResponse>();
        http_context.response->body = BytesBuffer(GetResponseBody());
        http_context.Finish();
        return SuccessExecutionResult();
      });

  absl::Notification finished;
  fetch_token_for_target_audience_context_.callback = [&finished](
                                                          auto& context) {
    EXPECT_THAT(context.result,
                ResultIs(RetryExecutionResult(
                    SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_BAD_SESSION_TOKEN)));
    finished.Notify();
  };
  EXPECT_THAT(authorizer_provider_->GetSessionTokenForTargetAudience(
                  fetch_token_for_target_audience_context_),
              IsSuccessful());

  finished.WaitForNotification();
}
}  // namespace google::scp::cpio::client_providers::test
