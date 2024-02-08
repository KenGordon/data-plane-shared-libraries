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

#include "cpio/client_providers/private_key_fetcher_provider/src/azure/azure_private_key_fetcher_provider.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <string>

#include "absl/strings/str_cat.h"
#include "core/http2_client/mock/mock_http_client.h"
#include "core/interface/async_context.h"
#include "absl/synchronization/notification.h"
#include "cpio/client_providers/auth_token_provider/mock/mock_auth_token_provider.h"
#include "cpio/client_providers/private_key_fetcher_provider/src/error_codes.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"

using google::scp::core::AsyncContext;
using google::scp::core::Byte;
using google::scp::core::BytesBuffer;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::errors::
    SC_PRIVATE_KEY_FETCHER_PROVIDER_HTTP_CLIENT_NOT_FOUND;
using google::scp::core::errors::
    SC_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND;
using google::scp::core::errors::
    SC_PRIVATE_KEY_FETCHER_PROVIDER_KEY_DATA_NOT_FOUND;
using google::scp::core::http2_client::mock::MockHttpClient;
using google::scp::core::test::IsSuccessful;
using google::scp::core::test::ResultIs;
using google::scp::cpio::client_providers::AzurePrivateKeyFetcherProvider;
using google::scp::cpio::client_providers::mock::MockAuthTokenProvider;
using std::atomic;
using testing::Pair;
using testing::Pointee;
using testing::Return;
using testing::SetArgPointee;
using testing::UnorderedElementsAre;
using ::testing::StrEq;

namespace {
constexpr char kAccountIdentity[] = "accountIdentity";
constexpr char kRegion[] = "us-east-1";
constexpr char kKeyId[] = "123";
constexpr char kPrivateKeyBaseUri[] = "http://localhost.test:8000";
constexpr char kSessionTokenMock[] = "session-token-test";
constexpr char kAuthorizationHeaderKey[] = "Authorization";
constexpr char kBearerTokenPrefix[] = "Bearer ";
}  // namespace

namespace google::scp::cpio::client_providers::test {
class AzurePrivateKeyFetcherProviderTest : public ::testing::Test {
 protected:
  AzurePrivateKeyFetcherProviderTest()
      : http_client_(std::make_shared<MockHttpClient>()),
        credentials_provider_(std::make_shared<MockAuthTokenProvider>()),
        azure_private_key_fetcher_provider_(
            std::make_unique<AzurePrivateKeyFetcherProvider>(
                http_client_, credentials_provider_)) {
    EXPECT_SUCCESS(azure_private_key_fetcher_provider_->Init());
    EXPECT_SUCCESS(azure_private_key_fetcher_provider_->Run());

    request_ = std::make_shared<PrivateKeyFetchingRequest>();
    request_->key_id = std::make_shared<std::string>(kKeyId);
    auto endpoint = std::make_shared<PrivateKeyVendingEndpoint>();
    endpoint->private_key_vending_service_endpoint = kPrivateKeyBaseUri;
    endpoint->service_region = kRegion;
    endpoint->account_identity = kAccountIdentity;
    request_->key_vending_endpoint = std::move(endpoint);
  }

  ~AzurePrivateKeyFetcherProviderTest() {
    if (azure_private_key_fetcher_provider_) {
      EXPECT_SUCCESS(azure_private_key_fetcher_provider_->Stop());
    }
  }

  void MockRequest(const std::string& uri) {
    http_client_->request_mock = HttpRequest();
    http_client_->request_mock.path = std::make_shared<std::string>(uri);
  }

  void MockResponse(const std::string& str) {
    http_client_->response_mock = HttpResponse();
    http_client_->response_mock.body = BytesBuffer(str);
  }

  std::shared_ptr<MockHttpClient> http_client_;
  std::shared_ptr<MockAuthTokenProvider> credentials_provider_;
  std::unique_ptr<AzurePrivateKeyFetcherProvider>
      azure_private_key_fetcher_provider_;
  std::shared_ptr<PrivateKeyFetchingRequest> request_;
};

TEST_F(AzurePrivateKeyFetcherProviderTest, MissingHttpClient) {
  azure_private_key_fetcher_provider_ =
      std::make_unique<AzurePrivateKeyFetcherProvider>(nullptr,
                                                     credentials_provider_);

  EXPECT_THAT(azure_private_key_fetcher_provider_->Init(),
              ResultIs(FailureExecutionResult(
                  SC_PRIVATE_KEY_FETCHER_PROVIDER_HTTP_CLIENT_NOT_FOUND)));
}

TEST_F(AzurePrivateKeyFetcherProviderTest, MissingCredentialsProvider) {
  azure_private_key_fetcher_provider_ =
      std::make_unique<AzurePrivateKeyFetcherProvider>(http_client_, nullptr);

  EXPECT_THAT(
      azure_private_key_fetcher_provider_->Init(),
      ResultIs(FailureExecutionResult(
          SC_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND)));
}

TEST_F(AzurePrivateKeyFetcherProviderTest, SignHttpRequest) {
  absl::Notification condition;
  AsyncContext<PrivateKeyFetchingRequest, HttpRequest> context(
      request_,
      [&](AsyncContext<PrivateKeyFetchingRequest, HttpRequest>& context) {
        EXPECT_SUCCESS(context.result);
        const auto& signed_request_ = *context.response;
        condition.Notify();
        return SuccessExecutionResult();
      });

  EXPECT_THAT(azure_private_key_fetcher_provider_->SignHttpRequest(context),
              IsSuccessful());
  condition.WaitForNotification();
}

TEST_F(AzurePrivateKeyFetcherProviderTest, FailedToGetCredentials) {
  EXPECT_CALL(*credentials_provider_,
              GetSessionToken)
      .WillOnce([=](AsyncContext<GetSessionTokenRequest,
                                 GetSessionTokenResponse>& context) {
        context.result = FailureExecutionResult(SC_UNKNOWN);
        context.Finish();
        return context.result;
      });

  absl::Notification condition;
  AsyncContext<PrivateKeyFetchingRequest, HttpRequest> context(
      request_,
      [&](AsyncContext<PrivateKeyFetchingRequest, HttpRequest>& context) {
        EXPECT_THAT(context.result,
                    ResultIs(FailureExecutionResult(SC_UNKNOWN)));
        condition.Notify();
      });

  EXPECT_THAT(azure_private_key_fetcher_provider_->SignHttpRequest(context),
              ResultIs(FailureExecutionResult(SC_UNKNOWN)));
  condition.WaitForNotification();
}

TEST_F(AzurePrivateKeyFetcherProviderTest, FetchPrivateKey) {
  MockRequest(std::string(kPrivateKeyBaseUri) + "/" + kKeyId);
  MockResponse(
      R"({
    "name": "encryptionKeys/123456",
    "encryptionKeyType": "SINGLE_PARTY_HYBRID_KEY",
    "publicKeysetHandle": "primaryKeyId",
    "publicKeyMaterial": "testtest",
    "creationTime": "1669252790485",
    "expirationTime": "1669943990485",
    "ttlTime": 0,
    "keyData": [
        {
            "publicKeySignature": "",
            "keyEncryptionKeyUri": "azu-kms://1234567",
            "keyMaterial": "test=test"
        },
        {
            "publicKeySignature": "",
            "keyEncryptionKeyUri": "azu-kms://12345",
            "keyMaterial": ""
        }
    ]
  })");

  absl::Notification condition;

  AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse> context(
      request_, [&](AsyncContext<PrivateKeyFetchingRequest,
                                 PrivateKeyFetchingResponse>& context) {
        EXPECT_SUCCESS(context.result);
        EXPECT_EQ(context.response->encryption_keys.size(), 1);
        const auto& encryption_key = *context.response->encryption_keys.begin();
        EXPECT_THAT(*encryption_key->resource_name,
                    StrEq("encryptionKeys/123456"));

        condition.Notify();
        return SuccessExecutionResult();
      });
  EXPECT_THAT(azure_private_key_fetcher_provider_->FetchPrivateKey(context),
              IsSuccessful());
  condition.WaitForNotification();
}

TEST_F(AzurePrivateKeyFetcherProviderTest, FailedToFetchPrivateKey) {
  ExecutionResult result = FailureExecutionResult(SC_UNKNOWN);
  http_client_->http_get_result_mock = result;

  absl::Notification condition;
  AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse> context(
      std::move(request_),
      [&](AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
              context) {
        condition.Notify();
        EXPECT_THAT(context.result, ResultIs(result));
      });
  EXPECT_THAT(azure_private_key_fetcher_provider_->FetchPrivateKey(context),
              IsSuccessful());
  condition.WaitForNotification();
}

TEST_F(AzurePrivateKeyFetcherProviderTest, PrivateKeyNotFound) {
  MockRequest(std::string(kPrivateKeyBaseUri) + "/" + kKeyId);
  MockResponse(
      R"({
        "name": "encryptionKeys/123456",
        "encryptionKeyType": "SINGLE_PARTY_HYBRID_KEY",
        "publicKeysetHandle": "primaryKeyId",
        "publicKeyMaterial": "testtest",
        "creationTime": "1669252790485",
        "expirationTime": "1669943990485",
        "ttlTime": 0
    })");

  absl::Notification condition;
  AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse> context(
      std::move(request_),
      [&](AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
              context) {
        condition.Notify();
        EXPECT_THAT(context.result,
                    ResultIs(FailureExecutionResult(
                        SC_PRIVATE_KEY_FETCHER_PROVIDER_KEY_DATA_NOT_FOUND)));
      });
  EXPECT_THAT(azure_private_key_fetcher_provider_->FetchPrivateKey(context),
              IsSuccessful());
  condition.WaitForNotification();
}

}  // namespace google::scp::cpio::client_providers::test
