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

#ifndef CPIO_CLIENT_PROVIDERS_ROLE_CREDENTIALS_PROVIDER_SRC_GCP_GCP_ROLE_CREDENTIALS_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_ROLE_CREDENTIALS_PROVIDER_SRC_GCP_GCP_ROLE_CREDENTIALS_PROVIDER_H_

#include "cpio/client_providers/interface/role_credentials_provider_interface.h"

namespace google::scp::cpio::client_providers {

class GcpRoleCredentialsProvider : public RoleCredentialsProviderInterface {
 public:
  core::ExecutionResult Init() noexcept override;

  core::ExecutionResult Run() noexcept override;

  core::ExecutionResult Stop() noexcept override;

  core::ExecutionResult GetRoleCredentials(
      core::AsyncContext<GetRoleCredentialsRequest, GetRoleCredentialsResponse>&
          get_credentials_context) noexcept override;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_ROLE_CREDENTIALS_PROVIDER_SRC_GCP_GCP_ROLE_CREDENTIALS_PROVIDER_H_
