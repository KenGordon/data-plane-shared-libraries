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

#ifndef CPIO_CLIENT_PROVIDERS_BLOB_STORAGE_CLIENT_PROVIDER_TEST_AWS_TEST_AWS_BLOB_STORAGE_CLIENT_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_BLOB_STORAGE_CLIENT_PROVIDER_TEST_AWS_TEST_AWS_BLOB_STORAGE_CLIENT_PROVIDER_H_

#include <memory>
#include <string>

#include <aws/core/Aws.h>
#include <aws/core/client/ClientConfiguration.h>

#include "cpio/client_providers/blob_storage_client_provider/src/aws/aws_blob_storage_client_provider.h"
#include "cpio/client_providers/interface/instance_client_provider_interface.h"
#include "public/cpio/test/blob_storage_client/test_aws_blob_storage_client_options.h"

namespace google::scp::cpio::client_providers {
/*! @copydoc AwsBlobStorageClientProvider
 */
class TestAwsBlobStorageClientProvider : public AwsBlobStorageClientProvider {
 public:
  TestAwsBlobStorageClientProvider(
      const std::shared_ptr<TestAwsBlobStorageClientOptions>& options,
      const std::shared_ptr<InstanceClientProviderInterface>&
          instance_client_provider,
      const std::shared_ptr<core::AsyncExecutorInterface>& cpu_async_executor,
      const std::shared_ptr<core::AsyncExecutorInterface>& io_async_executor)
      : AwsBlobStorageClientProvider(options, instance_client_provider,
                                     cpu_async_executor, io_async_executor),
        test_options_(options) {}

 protected:
  std::shared_ptr<Aws::Client::ClientConfiguration> CreateClientConfiguration(
      std::string_view region) noexcept override;

  std::shared_ptr<TestAwsBlobStorageClientOptions> test_options_;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_BLOB_STORAGE_CLIENT_PROVIDER_TEST_AWS_TEST_AWS_BLOB_STORAGE_CLIENT_PROVIDER_H_
