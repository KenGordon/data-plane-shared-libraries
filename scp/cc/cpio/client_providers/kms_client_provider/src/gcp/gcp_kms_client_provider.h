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

#ifndef CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_SRC_GCP_GCP_KMS_CLIENT_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_SRC_GCP_GCP_KMS_CLIENT_PROVIDER_H_

#include <memory>
#include <string>

#include <tink/aead.h>

#include "core/interface/async_context.h"
#include "cpio/client_providers/interface/kms_client_provider_interface.h"
#include "public/core/interface/execution_result.h"

#include "error_codes.h"
#include "gcp_kms_aead.h"

namespace google::scp::cpio::client_providers {
class GcpKmsAeadProvider;

/*! @copydoc KmsClientProviderInterface
 */
class GcpKmsClientProvider : public KmsClientProviderInterface {
 public:
  explicit GcpKmsClientProvider(
      const std::shared_ptr<GcpKmsAeadProvider>& aead_provider =
          std::make_shared<GcpKmsAeadProvider>())
      : aead_provider_(aead_provider) {}

  core::ExecutionResult Init() noexcept override;

  core::ExecutionResult Run() noexcept override;

  core::ExecutionResult Stop() noexcept override;

  core::ExecutionResult Decrypt(
      core::AsyncContext<cmrt::sdk::kms_service::v1::DecryptRequest,
                         cmrt::sdk::kms_service::v1::DecryptResponse>&
          decrypt_context) noexcept override;

 private:
  std::shared_ptr<GcpKmsAeadProvider> aead_provider_;
};

/// Provides GcpKmsAead.
class GcpKmsAeadProvider {
 public:
  /**
   * @brief Fetches KMS Aead.
   *
   * @param wip_provider WIP provider.
   * @param service_account_to_impersonate service account to impersonate.
   * @param key_name the key name used to create Aead.
   * @return core::ExecutionResultOr<std::shared_ptr<crypto::tink::Aead>> the
   * creation result.
   */
  virtual core::ExecutionResultOr<std::shared_ptr<crypto::tink::Aead>>
  CreateAead(std::string_view wip_provider,
             std::string_view service_account_to_impersonate,
             std::string_view key_name) noexcept;

 private:
  /**
   * @brief Creates KeyManagementServiceClient.
   *
   * @param wip_provider WIP provider.
   * @param service_account_to_impersonate servic account to impersonate.
   * @return
   * std::shared_ptr<cloud::kms::KeyManagementServiceClient> the
   * creation result.
   */
  std::shared_ptr<cloud::kms::KeyManagementServiceClient>
  CreateKeyManagementServiceClient(
      std::string_view wip_provider,
      std::string_view service_account_to_impersonate) noexcept;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_SRC_GCP_GCP_KMS_CLIENT_PROVIDER_H_
