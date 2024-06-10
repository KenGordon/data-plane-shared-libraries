/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "azure_auth_token_provider.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "absl/functional/bind_front.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "src/core/common/uuid/uuid.h"
#include "src/core/utils/base64.h"
#include "src/public/core/interface/execution_result.h"

#include "error_codes.h"

using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpClientInterface;
using google::scp::core::HttpHeaders;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::RetryExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::Uri;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::
    SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_BAD_SESSION_TOKEN;
using google::scp::core::errors::
    SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_INITIALIZATION_FAILED;
using google::scp::core::utils::Base64Decode;
using google::scp::core::utils::PadBase64Encoding;
using nlohmann::json;

namespace {
constexpr char kAzureAuthTokenProvider[] = "AzureAuthTokenProvider";
constexpr char kMetadataHeader[] = "Metadata";
constexpr char kMetadataHeaderValue[] = "true";

// Local IDP for Managed Identity.
// https://learn.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity
constexpr char kDefaultGetTokenUrl[] =
    "http://169.254.169.254/metadata/identity/oauth2/"
    "token?api-version=2018-02-01&resource=https%3A%2F%2Fprivacysandboxkms."
    "azure.net";
constexpr char kGetTokenUrlEnvVar[] = "AZURE_BA_PARAM_GET_TOKEN_URL";
constexpr char kJsonAccessTokenKey[] = "access_token";
constexpr char kJsonTokenExpiryKey[] = "expires_in";
constexpr char kJsonTokenExtendedExpiryKey[] = "ext_expires_in";
constexpr char kJsonTokenTypeKey[] = "token_type";

// Returns a pair of iterators - one to the beginning, one to the end.
const auto& GetRequiredJWTComponents() {
  static char const* components[4];
  using iterator_type = decltype(std::cbegin(components));
  static std::pair<iterator_type, iterator_type> iterator_pair = []() {
    components[0] = kJsonAccessTokenKey;
    components[1] = kJsonTokenExpiryKey;
    components[2] = kJsonTokenExtendedExpiryKey;
    components[3] = kJsonTokenTypeKey;
    return std::make_pair(std::cbegin(components), std::cend(components));
  }();
  return iterator_pair;
}
}  // namespace

namespace google::scp::cpio::client_providers {
AzureAuthTokenProvider::AzureAuthTokenProvider(
    absl::Nonnull<HttpClientInterface*> http_client)
    : http_client_(http_client), get_token_url_() {
  const char* value_from_env = std::getenv(kGetTokenUrlEnvVar);
  if (value_from_env) {
    get_token_url_ = value_from_env;
  } else {
    get_token_url_ = kDefaultGetTokenUrl;
  }
}

ExecutionResult AzureAuthTokenProvider::Init() noexcept {
  if (!http_client_) {
    auto execution_result = FailureExecutionResult(
        SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_INITIALIZATION_FAILED);
    SCP_ERROR(kAzureAuthTokenProvider, kZeroUuid, execution_result,
              "Http client cannot be nullptr.");
    return execution_result;
  }

  // Temporary workaround to configure the IDP URL.
  const char* value_from_env = std::getenv(kGetTokenUrlEnvVar);
  if (value_from_env) {
    get_token_url_ = value_from_env;
  } else {
    get_token_url_ = kDefaultGetTokenUrl;
  }

  return SuccessExecutionResult();
};

ExecutionResult AzureAuthTokenProvider::Run() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureAuthTokenProvider::Stop() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureAuthTokenProvider::GetSessionToken(
    AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>&
        get_token_context) noexcept {
  std::cout << "===============>AzureAuthTokenProvider::GetSessionToken" << std::endl;
  // Create request body
  AsyncContext<HttpRequest, HttpResponse> http_context;

  http_context.request = std::make_shared<HttpRequest>();

  http_context.request->method = google::scp::core::HttpMethod::GET;
  http_context.request->path = std::make_shared<Uri>(get_token_url_);
  std::cout << "===============>AzureAuthTokenProvider::GetSessionToken get_token_url_: " << get_token_url_ << std::endl;
  http_context.request->headers = std::make_shared<HttpHeaders>();
  http_context.request->headers->insert(
      std::make_pair(kMetadataHeader, kMetadataHeaderValue));
  http_context.callback =
      absl::bind_front(&AzureAuthTokenProvider::OnGetSessionTokenCallback, this,
                       get_token_context);

  auto execution_result = http_client_->PerformRequest(http_context);
  if (!execution_result.Successful()) {
  std::cout << "===============>AzureAuthTokenProvider::GetSessionToken failed: " << execution_result.status_code << std::endl;
    SCP_ERROR_CONTEXT(kAzureAuthTokenProvider, get_token_context,
                      execution_result,
                      "Failed to perform http request to fetch access token.");

    get_token_context.result = execution_result;
    get_token_context.Finish();
    return execution_result;
  }
  std::cout << "===============>AzureAuthTokenProvider::GetSessionToken success" << std::endl;

  return SuccessExecutionResult();
}

void AzureAuthTokenProvider::OnGetSessionTokenCallback(
    AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>&
        get_token_context,
    AsyncContext<HttpRequest, HttpResponse>& http_client_context) noexcept {
  std::cout << "===============>AzureAuthTokenProvider::OnGetSessionTokenCallback" << std::endl;
  if (!http_client_context.result.Successful()) {
    SCP_ERROR_CONTEXT(
        kAzureAuthTokenProvider, get_token_context, http_client_context.result,
        "Failed to get access token from Instance Metadata server");

    get_token_context.result = http_client_context.result;
    get_token_context.Finish();
    return;
  }

  json json_response;
  try {
    json_response =
        json::parse(http_client_context.response->body.bytes->begin(),
                    http_client_context.response->body.bytes->end());
    std::cout << "===============>AzureAuthTokenProvider::OnGetSessionTokenCallback response: " << std::string(http_client_context.response->body.bytes->begin(),
                    http_client_context.response->body.bytes->end()) << std::endl;

  } catch (...) {
    auto result = RetryExecutionResult(
        SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_BAD_SESSION_TOKEN);
    SCP_ERROR_CONTEXT(
        kAzureAuthTokenProvider, get_token_context, result,
        "Received http response could not be parsed into a JSON.");
    get_token_context.result = result;
    get_token_context.Finish();
    return;
  }
  std::cout << "===============>AzureAuthTokenProvider::OnGetSessionTokenCallback token retrieved" << std::endl;

  if (!std::all_of(GetRequiredJWTComponents().first,
                   GetRequiredJWTComponents().second,
                   [&json_response](const char* const component) {
                     return json_response.contains(component);
                   })) {
    auto result = RetryExecutionResult(
        SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_BAD_SESSION_TOKEN);
    SCP_ERROR_CONTEXT(
        kAzureAuthTokenProvider, get_token_context, result,
        "Received http response does not contain all the necessary fields.");
    get_token_context.result = result;
    get_token_context.Finish();
    return;
  }
  std::cout << "===============>AzureAuthTokenProvider::OnGetSessionTokenCallback token validated" << std::endl;

  get_token_context.response = std::make_shared<GetSessionTokenResponse>();

  uint64_t expiry_seconds = json_response[kJsonTokenExpiryKey].get<uint64_t>();
  get_token_context.response->token_lifetime_in_seconds =
      std::chrono::seconds(expiry_seconds);
  auto access_token = json_response[kJsonAccessTokenKey].get<std::string>();
  get_token_context.response->session_token =
      std::make_shared<std::string>(std::move(access_token));
  std::cout << "===============>AzureAuthTokenProvider::OnGetSessionTokenCallback token fields" << std::endl;

  get_token_context.result = SuccessExecutionResult();
  get_token_context.Finish();
}

ExecutionResult AzureAuthTokenProvider::GetSessionTokenForTargetAudience(
    AsyncContext<GetSessionTokenForTargetAudienceRequest,
                 GetSessionTokenResponse>& get_token_context) noexcept {
  // Not implemented.
  return FailureExecutionResult(SC_UNKNOWN);
}

std::unique_ptr<AuthTokenProviderInterface> AuthTokenProviderFactory::Create(
    absl::Nonnull<core::HttpClientInterface*> http1_client) {
  return std::make_unique<AzureAuthTokenProvider>(http1_client);
}

}  // namespace google::scp::cpio::client_providers
