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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AWS_AWS_PRIVATE_KEY_FETCHER_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AWS_AWS_PRIVATE_KEY_FETCHER_PROVIDER_H_
#include <memory>
#include <string>

#include "core/http2_client/src/aws/aws_v4_signer.h"
#include "core/interface/async_context.h"
#include "cpio/client_providers/interface/role_credentials_provider_interface.h"
#include "cpio/client_providers/private_key_fetcher_provider/src/private_key_fetcher_provider.h"
#include "public/core/interface/execution_result.h"

#include "error_codes.h"

namespace google::scp::cpio::client_providers {
/*! @copydoc PrivateKeyFetcherProviderInterface
 */
class AwsPrivateKeyFetcherProvider : public PrivateKeyFetcherProvider {
 public:
  /**
   * @brief Constructs a new AWS Private Key Fetching Client Provider object.
   *
   * @param http_client http client to issue http requests.
   * @param credentials_provider credentials provider.
   * service.
   */
  AwsPrivateKeyFetcherProvider(
      const std::shared_ptr<core::HttpClientInterface>& http_client,
      const std::shared_ptr<RoleCredentialsProviderInterface>&
          role_credentials_provider)
      : PrivateKeyFetcherProvider(http_client),
        role_credentials_provider_(role_credentials_provider) {}

  core::ExecutionResult Init() noexcept override;

  core::ExecutionResult SignHttpRequest(
      core::AsyncContext<PrivateKeyFetchingRequest, core::HttpRequest>&
          sign_http_request_context) noexcept override;

 protected:
  /**
   * @brief Triggered to sign Http request when session credentials are created.
   *
   * @param sign_http_request_context context to sign http request.
   * @param get_session_credentials_context context returned from session
   * credentials creation.
   * @param region AWS service region.
   */
  void CreateSessionCredentialsCallbackToSignHttpRequest(
      core::AsyncContext<PrivateKeyFetchingRequest, core::HttpRequest>&
          sign_http_request_context,
      core::AsyncContext<GetRoleCredentialsRequest, GetRoleCredentialsResponse>&
          get_session_credentials_context) noexcept;

  /**
   * @brief Signed Http request using AWS V4 Signer.
   *
   * @param http_request http request.
   * @param access_key AWS Access Key.
   * @param secret_key AWS Secret Key.
   * @param security_token AWS Security Token.
   * @param region AWS service region.
   */
  virtual core::ExecutionResult SignHttpRequestUsingV4Signer(
      std::shared_ptr<core::HttpRequest>& http_request,
      std::string_view access_key, std::string_view secret_key,
      std::string_view security_token, std::string_view region) noexcept;

  /// Credential provider.
  std::shared_ptr<RoleCredentialsProviderInterface> role_credentials_provider_;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AWS_AWS_PRIVATE_KEY_FETCHER_PROVIDER_H_
