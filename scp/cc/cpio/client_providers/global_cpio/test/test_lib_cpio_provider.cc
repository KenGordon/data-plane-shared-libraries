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

#include "test_lib_cpio_provider.h"

#include <memory>

#include "core/interface/async_executor_interface.h"
#include "cpio/client_providers/global_cpio/src/cpio_provider/lib_cpio_provider.h"
#include "cpio/client_providers/interface/cpio_provider_interface.h"
#include "public/cpio/interface/type_def.h"

#if defined(AWS_TEST)
#include "cpio/client_providers/instance_client_provider/test/aws/test_aws_instance_client_provider.h"
#include "cpio/client_providers/role_credentials_provider/test/aws/test_aws_role_credentials_provider.h"
#elif defined(GCP_TEST)
#include "cpio/client_providers/instance_client_provider/test/gcp/test_gcp_instance_client_provider.h"
#include "cpio/client_providers/role_credentials_provider/src/gcp/gcp_role_credentials_provider.h"
#else
#error "Must provide AWS_TEST or GCP_TEST"
#endif

using google::scp::core::AsyncExecutorInterface;

namespace google::scp::cpio::client_providers {
TestLibCpioProvider::TestLibCpioProvider(
    const std::shared_ptr<TestCpioOptions>& test_options)
    : LibCpioProvider(test_options), test_options_(test_options) {
#if defined(AWS_TEST)
  instance_client_provider_ = std::make_shared<TestAwsInstanceClientProvider>(
      std::make_shared<TestInstanceClientOptions>(*test_options_));
#elif defined(GCP_TEST)
  instance_client_provider_ = std::make_shared<TestGcpInstanceClientProvider>(
      std::make_shared<TestInstanceClientOptions>(*test_options_));
#endif
}

std::shared_ptr<RoleCredentialsProviderInterface>
TestLibCpioProvider::CreateRoleCredentialsProvider(
    const std::shared_ptr<InstanceClientProviderInterface>&
        instance_client_provider,
    const std::shared_ptr<AsyncExecutorInterface>& cpu_async_executor,
    const std::shared_ptr<AsyncExecutorInterface>& io_async_executor) noexcept {
#if defined(AWS_TEST)
  return std::make_shared<TestAwsRoleCredentialsProvider>(
      std::make_shared<TestAwsRoleCredentialsProviderOptions>(*test_options_),
      instance_client_provider, cpu_async_executor, io_async_executor);
#elif defined(GCP_TEST)
  return std::make_shared<GcpRoleCredentialsProvider>();
#endif
}

std::unique_ptr<CpioProviderInterface> CpioProviderFactory::Create(
    const std::shared_ptr<CpioOptions>& options) {
  return std::make_unique<TestLibCpioProvider>(
      std::dynamic_pointer_cast<TestCpioOptions>(options));
}
}  // namespace google::scp::cpio::client_providers
