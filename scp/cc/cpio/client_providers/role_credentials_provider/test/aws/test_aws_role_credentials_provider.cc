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

#include "test_aws_role_credentials_provider.h"

#include <memory>
#include <string>

#include <aws/core/Aws.h>
#include <aws/core/client/ClientConfiguration.h>

#include "cpio/client_providers/role_credentials_provider/src/aws/aws_role_credentials_provider.h"
#include "cpio/common/test/aws/test_aws_utils.h"

using Aws::Client::ClientConfiguration;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::ExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::cpio::common::test::CreateTestClientConfiguration;

namespace google::scp::cpio::client_providers {
std::shared_ptr<ClientConfiguration>
TestAwsRoleCredentialsProvider::CreateClientConfiguration(
    std::string_view region) noexcept {
  return CreateTestClientConfiguration(test_options_->sts_endpoint_override,
                                       std::make_shared<std::string>(region));
}

std::shared_ptr<RoleCredentialsProviderInterface>
RoleCredentialsProviderFactory::Create(
    const std::shared_ptr<RoleCredentialsProviderOptions>& options,
    const std::shared_ptr<InstanceClientProviderInterface>&
        instance_client_provider,
    const std::shared_ptr<core::AsyncExecutorInterface>& cpu_async_executor,
    const std::shared_ptr<core::AsyncExecutorInterface>&
        io_async_executor) noexcept {
  return std::make_shared<TestAwsRoleCredentialsProvider>(
      std::dynamic_pointer_cast<TestAwsRoleCredentialsProviderOptions>(options),
      instance_client_provider, cpu_async_executor, io_async_executor);
}
}  // namespace google::scp::cpio::client_providers
