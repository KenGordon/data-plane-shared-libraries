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

#include "aws_private_key_service_factory.h"

#include <memory>
#include <utility>
#include <vector>

#include "core/interface/service_interface.h"
#include "cpio/client_providers/auth_token_provider/src/aws/aws_auth_token_provider.h"
#include "cpio/client_providers/instance_client_provider/src/aws/aws_instance_client_provider.h"
#include "cpio/client_providers/interface/private_key_client_provider_interface.h"
#include "cpio/client_providers/private_key_client_provider/src/private_key_client_provider.h"
#include "cpio/client_providers/private_key_fetcher_provider/src/aws/aws_private_key_fetcher_provider.h"
#include "cpio/client_providers/role_credentials_provider/src/aws/aws_role_credentials_provider.h"
#include "cpio/server/interface/private_key_service/private_key_service_factory_interface.h"
#include "cpio/server/src/component_factory/component_factory.h"
#include "scp/cc/core/common/uuid/src/uuid.h"

using google::scp::core::ExecutionResult;
using google::scp::core::ExecutionResultOr;
using google::scp::core::HttpClientInterface;
using google::scp::core::ServiceInterface;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::common::kZeroUuid;
using google::scp::cpio::PrivateKeyClientOptions;
using google::scp::cpio::client_providers::AuthTokenProviderInterface;
using google::scp::cpio::client_providers::AwsAuthTokenProvider;
using google::scp::cpio::client_providers::AwsInstanceClientProvider;
using google::scp::cpio::client_providers::AwsPrivateKeyFetcherProvider;
using google::scp::cpio::client_providers::AwsRoleCredentialsProvider;
using google::scp::cpio::client_providers::InstanceClientProviderInterface;
using google::scp::cpio::client_providers::KmsClientProviderInterface;
using google::scp::cpio::client_providers::PrivateKeyFetcherProviderInterface;
using google::scp::cpio::client_providers::RoleCredentialsProviderInterface;

namespace {
constexpr char kAwsPrivateKeyServiceFactory[] = "AwsPrivateKeyServiceFactory";
}  // namespace

namespace google::scp::cpio {
ExecutionResultOr<std::shared_ptr<ServiceInterface>>
AwsPrivateKeyServiceFactory::CreateAuthTokenProvider() noexcept {
  auth_token_provider_ = std::make_shared<AwsAuthTokenProvider>(http1_client_);
  return auth_token_provider_;
}

ExecutionResultOr<std::shared_ptr<ServiceInterface>>
AwsPrivateKeyServiceFactory::CreateInstanceClient() noexcept {
  instance_client_ = std::make_shared<AwsInstanceClientProvider>(
      auth_token_provider_, http1_client_, cpu_async_executor_,
      io_async_executor_);
  return instance_client_;
}

ExecutionResultOr<std::shared_ptr<ServiceInterface>>
AwsPrivateKeyServiceFactory::CreatePrivateKeyFetcher() noexcept {
  private_key_fetcher_ = std::make_shared<AwsPrivateKeyFetcherProvider>(
      http2_client_, role_credentials_provider_);
  return private_key_fetcher_;
}

ExecutionResultOr<std::shared_ptr<ServiceInterface>>
AwsPrivateKeyServiceFactory::CreateRoleCredentialsProvider() noexcept {
  role_credentials_provider_ = std::make_shared<AwsRoleCredentialsProvider>(
      instance_client_, cpu_async_executor_, io_async_executor_);
  return role_credentials_provider_;
}

ExecutionResult AwsPrivateKeyServiceFactory::Init() noexcept {
  RETURN_AND_LOG_IF_FAILURE(ReadConfigurations(), kAwsPrivateKeyServiceFactory,
                            kZeroUuid, "Failed to read configurations");

  std::vector<ComponentCreator> creators(
      {ComponentCreator([this] { return CreateIoAsyncExecutor(); },
                        "IoAsyncExecutor"),
       ComponentCreator([this] { return CreateCpuAsyncExecutor(); },
                        "CpuAsyncExecutor"),
       ComponentCreator([this] { return CreateHttp1Client(); }, "Http1Client"),
       ComponentCreator([this] { return CreateHttp2Client(); }, "Http2Client"),
       ComponentCreator([this] { return CreateAuthTokenProvider(); },
                        "AuthTokenProvider"),
       ComponentCreator([this] { return CreateInstanceClient(); },
                        "InstanceClient"),
       ComponentCreator([this] { return CreateRoleCredentialsProvider(); },
                        "RoleCredentialsProvider"),
       ComponentCreator([this] { return CreatePrivateKeyFetcher(); },
                        "PrivateKeyFetcher"),
       ComponentCreator([this] { return CreateKmsClient(); }, "KmsClient")});
  component_factory_ = std::make_shared<ComponentFactory>(std::move(creators));

  RETURN_AND_LOG_IF_FAILURE(PrivateKeyServiceFactory::Init(),
                            kAwsPrivateKeyServiceFactory, kZeroUuid,
                            "Failed to init PrivateKeyServiceFactory.");

  return SuccessExecutionResult();
}
}  // namespace google::scp::cpio
