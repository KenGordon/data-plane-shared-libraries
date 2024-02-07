/*
 * Copyright 2022 Google LLC
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
#include "core/utils/src/base64.h"
#include "scp/cc/core/common/uuid/src/uuid.h"

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

constexpr char kIdentityServerPath[] =
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/"
    "identity";
constexpr char kMetadataFlavorHeader[] = "Metadata-Flavor";
constexpr char kMetadataFlavorHeaderValue[] = "Google";
constexpr char kJsonAccessTokenKey[] = "access_token";
constexpr char kJsonTokenExpiryKey[] = "expires_in";
constexpr char kJsonTokenTypeKey[] = "token_type";
constexpr char kAudienceParameter[] = "audience=";
constexpr char kFormatFullParameter[] = "format=full";

constexpr size_t kExpectedTokenPartsSize = 3;
constexpr char kJsonTokenIssuerKey[] = "iss";
constexpr char kJsonTokenAudienceKey[] = "aud";
constexpr char kJsonTokenSubjectKey[] = "sub";
constexpr char kJsonTokenIssuedAtKey[] = "iat";
constexpr char kJsonTokenExpiryKeyForTargetAudience[] = "exp";

// Returns a pair of iterators - one to the beginning, one to the end.
const auto& GetRequiredJWTComponents() {
  static char const* components[3];
  using iterator_type = decltype(std::cbegin(components));
  static std::pair<iterator_type, iterator_type> iterator_pair = []() {
    components[0] = kJsonAccessTokenKey;
    components[1] = kJsonTokenExpiryKey;
    components[2] = kJsonTokenTypeKey;
    return std::make_pair(std::cbegin(components), std::cend(components));
  }();
  return iterator_pair;
}

// Returns a pair of iterators - one to the beginning, one to the end.
const auto& GetRequiredJWTComponentsForTargetAudienceToken() {
  static char const* components[5];
  using iterator_type = decltype(std::cbegin(components));
  static std::pair<iterator_type, iterator_type> iterator_pair = []() {
    components[0] = kJsonTokenIssuerKey;
    components[1] = kJsonTokenAudienceKey;
    components[2] = kJsonTokenSubjectKey;
    components[3] = kJsonTokenIssuedAtKey;
    components[4] = kJsonTokenExpiryKeyForTargetAudience;
    return std::make_pair(std::cbegin(components), std::cend(components));
  }();
  return iterator_pair;
}
}  // namespace

namespace google::scp::cpio::client_providers {
AzureAuthTokenProvider::AzureAuthTokenProvider(
    const std::shared_ptr<HttpClientInterface>& http_client)
    : http_client_(http_client) {}

ExecutionResult AzureAuthTokenProvider::Init() noexcept {
  if (!http_client_) {
    auto execution_result = FailureExecutionResult(
        SC_AZURE_INSTANCE_AUTHORIZER_PROVIDER_INITIALIZATION_FAILED);
    SCP_ERROR(kAzureAuthTokenProvider, kZeroUuid, execution_result,
              "Http client cannot be nullptr.");
    return execution_result;
  }

  return SuccessExecutionResult();
};

ExecutionResult AzureAuthTokenProvider::Run() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureAuthTokenProvider::Stop() noexcept {
  return SuccessExecutionResult();
}

std::string AzureAuthTokenProvider::GetEnvVar(std::string name) {
const char* value_from_env = std::getenv(name.c_str());
  if (value_from_env) {
    return std::string(value_from_env);
  } else {
      // throw std::runtime_error("Environment variable not found: " + name);
    return "";
  }
}

ExecutionResult AzureAuthTokenProvider::GetSessionToken(
    AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>&
        get_token_context) noexcept {

  std::cout << "TEST_TAKURO: GetSessionToken\n";
  std::string endpoint = GetEnvVar("AZURE_AAD_ENDPOINT");
  std::string clientid = GetEnvVar("AZURE_CLIENT_ID");
  std::string clientSecret = GetEnvVar("AZURE_CLIENT_SECRET");
  std::string apiApplicationId = GetEnvVar("AZURE_API_APPLICATION_ID");

  // Create request body
  std::ostringstream request_body_stream;
  request_body_stream << "client_id=" << clientid
                      << "&client_secret=" << clientSecret
                      << "&scope=" << apiApplicationId
                      << "/.default"
                      << "&grant_type=client_credentials";
  std::string request_body = request_body_stream.str();
  AsyncContext<HttpRequest, HttpResponse> http_context;

  http_context.request = std::make_shared<HttpRequest>();

  http_context.request->method = google::scp::core::HttpMethod::POST;
  http_context.request->path = std::make_shared<Uri>(endpoint);
  http_context.request->headers = std::make_shared<HttpHeaders>();
  http_context.request->headers->insert(
      std::make_pair("Content-Type", "application/x-www-form-urlencoded"));
  http_context.request->body = google::scp::core::BytesBuffer(request_body);
  http_context.callback =
      absl::bind_front(&AzureAuthTokenProvider::OnGetSessionTokenCallback, this,
                       get_token_context);

  auto execution_result = http_client_->PerformRequest(http_context);
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(kAzureAuthTokenProvider, get_token_context,
                      execution_result,
                      "Failed to perform http request to fetch access token.");

    get_token_context.result = execution_result;
    get_token_context.Finish();
    return execution_result;
  }

  return SuccessExecutionResult();
}

void AzureAuthTokenProvider::OnGetSessionTokenCallback(
    AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>&
        get_token_context,
    AsyncContext<HttpRequest, HttpResponse>& http_client_context) noexcept {
  if (!http_client_context.result.Successful()) {
    SCP_ERROR_CONTEXT(
        kAzureAuthTokenProvider, get_token_context, http_client_context.result,
        "Failed to get access token from Instance Metadata server");

    get_token_context.result = http_client_context.result;
    get_token_context.Finish();
    return;
  }

  std::cout << "TEST_TAKURO: got token\n";

  json json_response;
  try {
    json_response =
        json::parse(http_client_context.response->body.bytes->begin(),
                    http_client_context.response->body.bytes->end());
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

  get_token_context.response = std::make_shared<GetSessionTokenResponse>();

  // The life time of GCP access token is about 1 hour.
  uint64_t expiry_seconds = json_response[kJsonTokenExpiryKey].get<uint64_t>();
  get_token_context.response->token_lifetime_in_seconds =
      std::chrono::seconds(expiry_seconds);
  auto access_token = json_response[kJsonAccessTokenKey].get<std::string>();
  get_token_context.response->session_token =
      std::make_shared<std::string>(std::move(access_token));

  get_token_context.result = SuccessExecutionResult();
  get_token_context.Finish();
}

ExecutionResult AzureAuthTokenProvider::GetSessionTokenForTargetAudience(
    AsyncContext<GetSessionTokenForTargetAudienceRequest,
                 GetSessionTokenResponse>& get_token_context) noexcept {
  // Not implemented.
  return FailureExecutionResult(SC_UNKNOWN);
}


std::shared_ptr<AuthTokenProviderInterface> AuthTokenProviderFactory::Create(
    const std::shared_ptr<core::HttpClientInterface>& http1_client) {
  return std::make_shared<AzureAuthTokenProvider>(http1_client);
}
}  // namespace google::scp::cpio::client_providers
