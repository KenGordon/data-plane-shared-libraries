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

#include "azure_kms_client_provider.h"

#include <cstdlib>
#include <utility>

#include <nlohmann/json.hpp>

#include "absl/functional/bind_front.h"
#include "absl/log/check.h"
#include "core/utils/src/base64.h"
#include "cpio/client_providers/global_cpio/src/global_cpio.h"
#include "cpio/client_providers/interface/auth_token_provider_interface.h"
#include "cpio/client_providers/interface/kms_client_provider_interface.h"
#include "cpio/client_providers/private_key_fetcher_provider/src/azure/azure_private_key_fetcher_provider_utils.h"
#include "proto/hpke.pb.h"
#include "public/cpio/interface/kms_client/type_def.h"

#include "error_codes.h"

using google::cmrt::sdk::kms_service::v1::DecryptRequest;
using google::cmrt::sdk::kms_service::v1::DecryptResponse;
using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutorInterface;
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
    SC_AZURE_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND;
using google::scp::core::errors::SC_AZURE_KMS_CLIENT_PROVIDER_KEY_ID_NOT_FOUND;
using google::scp::core::errors::
    SC_AZURE_KMS_CLIENT_PROVIDER_WRAPPING_KEY_GENERATION_ERROR;
using google::scp::core::utils::Base64Decode;
using google::scp::core::utils::Base64Encode;
using google::scp::cpio::client_providers::AzurePrivateKeyFetchingClientUtils;
using google::scp::cpio::client_providers::EvpPkeyWrapper;
using std::all_of;
using std::bind;
using std::cbegin;
using std::cend;
using std::make_pair;
using std::make_shared;
using std::pair;
using std::shared_ptr;
using std::placeholders::_1;

namespace google::scp::cpio::client_providers {

static constexpr char kAzureKmsClientProvider[] = "AzureKmsClientProvider";
static constexpr char kPemSeperator[] = "-----";
static constexpr char kPemEnd[] = "END ";
static constexpr char kPemToken[] = "PRIVATE ";
static constexpr char kPemKey[] = "KEY";
static constexpr char kPemBegin[] = "BEGIN ";
static constexpr char kWrappingKp[] = R"(
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
/Kg7pJF1e2hkk3vxtCSlu9HfZ4q17vg=
)";

constexpr char kDefaultKmsUnwrapPath[] =
    "https://127.0.0.1:8000/app/unwrapKey?fmt=tink";
constexpr char kAzureKmsUnwrapUrlEnvVar[] = "AZURE_BA_PARAM_KMS_UNWRAP_URL";

constexpr char kAuthorizationHeaderKey[] = "Authorization";
constexpr char kBearerTokenPrefix[] = "Bearer ";

ExecutionResult AzureKmsClientProvider::Init() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureKmsClientProvider::Run() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureKmsClientProvider::Stop() noexcept {
  return SuccessExecutionResult();
}

// add test keys for non-SNP environment
std::string GetTestPemPublicWrapKey() {
  return R"(
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0L9FDBjydkdstv7OKqkw
dMiugRqlSHC9Lchfd7jh5uCzv602LhlBJQeEFYchvaEquISLQFoZxEkpGEbEb15v
N2dKwTCi0ioEGBidtFmuKiVZqf46Hbnw4OdinQHrlGO2PRsRE+DYPOy6xrZTKEnD
K+OnHDsZ0U2qNJ80IjbxcC83lQpaMx8Ij8AddGY9Msv0TMMgaVsrDaQYLC8tmJih
xVI2f5BHFbTy3pw4Sq9xp6se+S/ycOUF0M6RFArZcD9uR/NxJKFJJlGOKskgwLnT
lhPck4sGeLhHUydRdqw0+h8EDsTIUysNxMOYtZETaVuBS+ISMy8+WQgVPs12Ujr3
17kaHeZr8Lq0bwaFHruRBpNwqtUCBv57IBpe7hnEDDdvOvN/tPubf1dv3HxEt42T
qqfozS+a9+1hcI8hpNlEjh+qcy1BmhSOXvmRzlhauX4xv6OLCNkRxo6x2Q/1moDC
PgnaJJVIuESr07xnC8fk43i5qFzEXQO3hwNsjd7sqFBBTb6t5N6Nm37mMNTqsDky
niAeFG+1gK/UD+cMPfbUIDaCqpCDwrTX0gMqqUTDG6eNPmQaOa+slici3h9WLaNy
mEzfKqJMBggKib/+e4Eb/ENdvxeT1X2YXpZ3tjZE+bRoiDgN4FYqBzYtZ/ieRcsq
4fPqgZPbh+ivT2o7QutzWH0CAwEAAQ==
-----END PUBLIC KEY-----

)";
}

std::string GetTestPemPrivWrapKey() {
  std::string result = std::string(kPemSeperator) + kPemBegin + kPemToken +
                       kPemKey + kPemSeperator + "\n" + kWrappingKp +
                       kPemSeperator + kPemEnd + kPemToken + kPemKey +
                       kPemSeperator + "\n";
  return result;
}

ExecutionResult AzureKmsClientProvider::Decrypt(
    core::AsyncContext<DecryptRequest, DecryptResponse>&
        decrypt_context) noexcept {
  auto get_credentials_request = std::make_shared<GetSessionTokenRequest>();
  AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>
      get_token_context(
          std::move(get_credentials_request),
          absl::bind_front(
              &AzureKmsClientProvider::GetSessionCredentialsCallbackToDecrypt,
              this, decrypt_context),
          decrypt_context);

  return auth_token_provider_->GetSessionToken(get_token_context);
}

void AzureKmsClientProvider::GetSessionCredentialsCallbackToDecrypt(
    core::AsyncContext<DecryptRequest, DecryptResponse>& decrypt_context,
    core::AsyncContext<GetSessionTokenRequest, GetSessionTokenResponse>&
        get_token_context) noexcept {
  if (!get_token_context.result.Successful()) {
    SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                      get_token_context.result,
                      "Failed to get the access token.");
    decrypt_context.result = get_token_context.result;
    decrypt_context.Finish();
    return;
  }

  const auto& access_token = *get_token_context.response->session_token;

  const auto& ciphertext = decrypt_context.request->ciphertext();

  if (ciphertext.empty()) {
    auto execution_result = FailureExecutionResult(
        SC_AZURE_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND);
    SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to get cipher text from decryption request.");
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return;
  }

  // Check that there is an ID for the key to decrypt with
  const auto& key_id = decrypt_context.request->key_resource_name();
  if (key_id.empty()) {
    auto execution_result =
        FailureExecutionResult(SC_AZURE_KMS_CLIENT_PROVIDER_KEY_ID_NOT_FOUND);
    SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to get Key ID from decryption request.");
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return;
  }

  AsyncContext<HttpRequest, HttpResponse> http_context;
  http_context.request = std::make_shared<HttpRequest>();

  // For the first call, it tries to get the unwrap URL from environment
  // variable. This is done here because Init() is not called by the shared code
  // and it's a temporary workaround.
  if (unwrap_url_.empty()) {
    const char* value_from_env = std::getenv(kAzureKmsUnwrapUrlEnvVar);
    if (value_from_env) {
      unwrap_url_ = value_from_env;
    } else {
      unwrap_url_ = kDefaultKmsUnwrapPath;
    }
  }

  http_context.request->path = std::make_shared<Uri>(unwrap_url_);
  http_context.request->method = HttpMethod::POST;

  // Get Attestation Report
  const auto report =
      hasSnp() ? fetchSnpAttestation() : fetchFakeSnpAttestation();
  CHECK(report.has_value()) << "Failed to get attestation report";

  EVP_PKEY* publicKey;
  EVP_PKEY* privateKey;

  // Temporary store wrappingKey
  std::pair<std::shared_ptr<EvpPkeyWrapper>, std::shared_ptr<EvpPkeyWrapper>> wrappingKeyPair;
  if (hasSnp()) {
    // Generate wrapping key
    try {
      wrappingKeyPair = AzurePrivateKeyFetchingClientUtils::GenerateWrappingKey();
    } catch (const std::runtime_error& e) {
      std::string errorMessage = "Failed to generate wrapping key : ";
      errorMessage += e.what();
      auto execution_result = FailureExecutionResult(
          SC_AZURE_KMS_CLIENT_PROVIDER_WRAPPING_KEY_GENERATION_ERROR);

      SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                        execution_result, errorMessage);
      decrypt_context.result = execution_result;
      decrypt_context.Finish();
      return;
    }

    privateKey = wrappingKeyPair.first->get();
    publicKey = wrappingKeyPair.second->get();
  } else {
    // Get test PEM public key
    auto publicPemKey = GetTestPemPublicWrapKey();
    publicKey = AzurePrivateKeyFetchingClientUtils::PemToEvpPkey(publicPemKey);

    // Get test PEM private key and convert it to EVP_PKEY*
    auto privateKeyPem = GetTestPemPrivWrapKey();
    privateKey = nullptr;
    BIOWrapper bioWrapper(const_cast<BIO_METHOD*>(BIO_s_mem()));

    // Get the BIO object from the wrapper
    BIO* bio = bioWrapper.get();
    if (bio == nullptr) {
      char* error_string = ERR_error_string(ERR_get_error(), nullptr);
      throw std::runtime_error(std::string("Failed to create BIO: ") +
                               error_string);
    }

    BIO_write(bio, privateKeyPem.c_str(), privateKeyPem.size());
    PEM_read_bio_PrivateKey(bio, &privateKey, nullptr, nullptr);
    wrappingKeyPair = std::make_pair(
      std::make_shared<EvpPkeyWrapper>(privateKey),
      std::make_shared<EvpPkeyWrapper>(publicKey));
  }

  
  nlohmann::json payload;
  payload[kWrapped] = ciphertext;
  payload[kWrappedKid] = key_id;
  payload[kAttestation] = nlohmann::json(report.value());
  payload[kWrappingKey] =
      AzurePrivateKeyFetchingClientUtils::EvpPkeyToPem(publicKey);

  http_context.request->body = core::BytesBuffer(nlohmann::to_string(payload));
  http_context.request->headers = std::make_shared<core::HttpHeaders>();
  http_context.request->headers->insert(
      {std::string(kAuthorizationHeaderKey),
       absl::StrCat(kBearerTokenPrefix, access_token)});

  // auto p = std::make_unique<EvpPkeyWrapper>(new EvpPkeyWrapper(privateKey));

  http_context.callback = bind(&AzureKmsClientProvider::OnDecryptCallback, this,
                               decrypt_context, wrappingKeyPair.first, _1);
                               
  auto execution_result = http_client_->PerformRequest(http_context);
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to perform http request to decrypt wrapped key.");

    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return;
  }
}

void AzureKmsClientProvider::OnDecryptCallback(
    AsyncContext<DecryptRequest, DecryptResponse>& decrypt_context,
    std::shared_ptr<EvpPkeyWrapper> ephemeral_private_key,
    AsyncContext<HttpRequest, HttpResponse>& http_client_context) noexcept {
  if (!http_client_context.result.Successful()) {
    SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                      http_client_context.result,
                      "Failed to decrypt wrapped key using Azure KMS");
    decrypt_context.result = http_client_context.result;
    decrypt_context.Finish();
    return;
  }
  std::string resp(http_client_context.response->body.bytes->begin(),
                   http_client_context.response->body.bytes->end());
  nlohmann::json unwrapResp;
  try {
    unwrapResp = nlohmann::json::parse(resp);
  } catch (const nlohmann::json::parse_error& e) {
    SCP_ERROR_CONTEXT(kAzureKmsClientProvider, decrypt_context,
                      http_client_context.result,
                      "Failed to parse response from Azure KMS unwrapKey");
    decrypt_context.result = http_client_context.result;
    decrypt_context.Finish();
    return;
  }
  std::string decodedWrapped;
  if (auto execution_result =
          Base64Decode(unwrapResp[kWrapped], decodedWrapped);
      !execution_result.Successful()) {
    SCP_ERROR_CONTEXT(
        kAzureKmsClientProvider, decrypt_context, http_client_context.result,
        "Failed to base64 decode response from Azure KMS unwrapKey");
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return;
  }
  std::vector<uint8_t> encrypted(decodedWrapped.begin(), decodedWrapped.end());

  std::string decrypted = AzurePrivateKeyFetchingClientUtils::KeyUnwrap(
      ephemeral_private_key->get(), encrypted);
  decrypt_context.response = std::make_shared<DecryptResponse>();

  decrypt_context.response->set_plaintext(decrypted);

  decrypt_context.result = SuccessExecutionResult();
  decrypt_context.Finish();
}

#ifndef TEST_CPIO
shared_ptr<KmsClientProviderInterface> KmsClientProviderFactory::Create(
    const shared_ptr<KmsClientOptions>& options,
    const shared_ptr<RoleCredentialsProviderInterface>&
        role_credentials_provider,
    const shared_ptr<AsyncExecutorInterface>& io_async_executor) noexcept {
  // We uses GlobalCpio::GetGlobalCpio()->GetHttpClient() to get http_client
  // object instead of adding it to KmsClientProviderFactory::Create() as a new
  // parameter. This is to prevent the existing GCP and AWS implementations from
  // being changed.
  std::shared_ptr<core::HttpClientInterface> http_client;
  auto execution_result =
      GlobalCpio::GetGlobalCpio()->GetHttpClient(http_client);
  CHECK(execution_result.Successful()) << "failed to get http client";
  std::shared_ptr<AuthTokenProviderInterface> auth_token_provider;
  execution_result =
      GlobalCpio::GetGlobalCpio()->GetAuthTokenProvider(auth_token_provider);
  CHECK(execution_result.Successful()) << "failed to get auth token provider";
  return make_shared<AzureKmsClientProvider>(http_client, auth_token_provider);
}
#endif
}  // namespace google::scp::cpio::client_providers