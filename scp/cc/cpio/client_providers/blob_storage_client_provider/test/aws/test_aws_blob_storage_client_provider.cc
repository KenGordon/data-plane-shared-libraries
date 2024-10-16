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

#include "test_aws_blob_storage_client_provider.h"

#include <memory>
#include <string>

#include <aws/core/Aws.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/s3/S3Client.h>

#include "cpio/client_providers/interface/instance_client_provider_interface.h"
#include "cpio/common/test/aws/test_aws_utils.h"
#include "public/cpio/interface/blob_storage_client/type_def.h"
#include "public/cpio/test/blob_storage_client/test_aws_blob_storage_client_options.h"

using Aws::Client::ClientConfiguration;
using Aws::S3::S3Client;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::ExecutionResult;
using google::scp::core::ExecutionResultOr;
using google::scp::core::SuccessExecutionResult;
using google::scp::cpio::common::test::CreateTestClientConfiguration;

namespace google::scp::cpio::client_providers {
std::shared_ptr<ClientConfiguration>
TestAwsBlobStorageClientProvider::CreateClientConfiguration(
    std::string_view region) noexcept {
  return CreateTestClientConfiguration(test_options_->s3_endpoint_override,
                                       std::make_shared<std::string>(region));
}

ExecutionResultOr<std::shared_ptr<S3Client>> AwsS3Factory::CreateClient(
    ClientConfiguration& client_config,
    const std::shared_ptr<AsyncExecutorInterface>& async_executor) noexcept {
  // Should disable virtual host, otherwise, our path-style url will not work.
  return std::make_shared<S3Client>(
      client_config, Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never,
      /* use virtual host */ false);
}

std::shared_ptr<BlobStorageClientProviderInterface>
BlobStorageClientProviderFactory::Create(
    std::shared_ptr<BlobStorageClientOptions> options,
    std::shared_ptr<InstanceClientProviderInterface> instance_client_provider,
    const std::shared_ptr<AsyncExecutorInterface>& cpu_async_executor,
    const std::shared_ptr<AsyncExecutorInterface>& io_async_executor) noexcept {
  return std::make_shared<TestAwsBlobStorageClientProvider>(
      std::dynamic_pointer_cast<TestAwsBlobStorageClientOptions>(options),
      instance_client_provider, cpu_async_executor, io_async_executor);
}
}  // namespace google::scp::cpio::client_providers
