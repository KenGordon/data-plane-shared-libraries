
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

#include "test_gcp_blob_storage_client_provider.h"

#include "cpio/client_providers/interface/instance_client_provider_interface.h"
#include "google/cloud/credentials.h"
#include "google/cloud/options.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/blob_storage_client/type_def.h"
#include "public/cpio/test/blob_storage_client/test_gcp_blob_storage_client_options.h"

using google::cloud::MakeGoogleDefaultCredentials;
using google::cloud::MakeImpersonateServiceAccountCredentials;
using google::cloud::Options;
using google::scp::core::AsyncExecutorInterface;

namespace google::scp::cpio::client_providers {
Options TestGcpCloudStorageFactory::CreateClientOptions(
    std::shared_ptr<BlobStorageClientOptions> options,
    std::string_view project_id) noexcept {
  Options client_options =
      GcpCloudStorageFactory::CreateClientOptions(options, project_id);
  auto test_options =
      std::dynamic_pointer_cast<TestGcpBlobStorageClientOptions>(options);
  if (!test_options->impersonate_service_account.empty()) {
    client_options.set<google::cloud::UnifiedCredentialsOption>(
        (MakeImpersonateServiceAccountCredentials(
            google::cloud::MakeGoogleDefaultCredentials(),
            test_options->impersonate_service_account)));
  }
  return client_options;
}

std::shared_ptr<BlobStorageClientProviderInterface>
BlobStorageClientProviderFactory::Create(
    std::shared_ptr<BlobStorageClientOptions> options,
    std::shared_ptr<InstanceClientProviderInterface> instance_client_provider,
    const std::shared_ptr<AsyncExecutorInterface>& cpu_async_executor,
    const std::shared_ptr<AsyncExecutorInterface>& io_async_executor) noexcept {
  return make_shared<GcpBlobStorageClientProvider>(
      options, instance_client_provider, cpu_async_executor, io_async_executor,
      std::make_shared<TestGcpCloudStorageFactory>());
}
}  // namespace google::scp::cpio::client_providers
