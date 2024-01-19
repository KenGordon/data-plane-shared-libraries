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

#include "azure_parameter_client_provider.h"

#include <memory>
#include <string>
#include <utility>
#include <cstdlib>

#include "absl/strings/str_format.h"
#include "absl/log/check.h"
#include "core/common/uuid/src/uuid.h"
#include "core/interface/async_context.h"
#include "google/cloud/secretmanager/secret_manager_client.h"
#include "google/cloud/secretmanager/secret_manager_connection.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/proto/parameter_service/v1/parameter_service.pb.h"

#include "error_codes.h"

using google::cloud::StatusCode;
using google::cloud::StatusOr;
using google::cloud::secretmanager::MakeSecretManagerServiceConnection;
using google::cloud::secretmanager::SecretManagerServiceClient;
using google::cloud::secretmanager::v1::AccessSecretVersionRequest;
using google::cloud::secretmanager::v1::AccessSecretVersionResponse;
using google::cmrt::sdk::parameter_service::v1::GetParameterRequest;
using google::cmrt::sdk::parameter_service::v1::GetParameterResponse;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncPriority;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::
    SC_AZURE_PARAMETER_CLIENT_PROVIDER_PARAMETER_NOT_FOUND;
using google::scp::core::errors::
    SC_AZURE_PARAMETER_CLIENT_PROVIDER_INVALID_PARAMETER_NAME;
using std::bind;
using std::placeholders::_1;

static constexpr char kAzureParameterClientProvider[] =
    "AzureParameterClientProvider";

namespace google::scp::cpio::client_providers {
ExecutionResult AzureParameterClientProvider::Init() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureParameterClientProvider::Run() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult AzureParameterClientProvider::Stop() noexcept {
  return SuccessExecutionResult();
}

std::shared_ptr<SecretManagerServiceClient>
AzureParameterClientProvider::GetSecretManagerClient() noexcept {
  return std::make_shared<SecretManagerServiceClient>(
      MakeSecretManagerServiceConnection());
}

ExecutionResult AzureParameterClientProvider::GetParameter(
    AsyncContext<GetParameterRequest, GetParameterResponse>&
        get_parameter_context) noexcept {
  get_parameter_context.response = std::make_shared<GetParameterResponse>();
  const auto& parameter_name = get_parameter_context.request->parameter_name();
  // The `parameter_name` follows the format of <prefix>-<parameter name>, and the prefix
  // consists of the values from `instance_client_provider`. Our instance client
  // always returns the same dummy values for the current implementation.
  // So we can just ignore the prefix for now.
  const std::string prefix = "azure_operator-azure_environment-";

  if (parameter_name.empty()) {
    auto execution_result = FailureExecutionResult(
        SC_AZURE_PARAMETER_CLIENT_PROVIDER_INVALID_PARAMETER_NAME);
    SCP_ERROR_CONTEXT(kAzureParameterClientProvider, get_parameter_context,
                      execution_result, "Failed due to an empty parameter.");
    get_parameter_context.result = execution_result;
    get_parameter_context.Finish();
    return execution_result;
  }

  if (parameter_name.size() <= prefix.size() || parameter_name.substr(0, prefix.size()) != prefix) {
    auto execution_result = FailureExecutionResult(
        SC_AZURE_PARAMETER_CLIENT_PROVIDER_INVALID_PARAMETER_NAME);
    SCP_ERROR_CONTEXT(kAzureParameterClientProvider, get_parameter_context,
                      execution_result, "Request does not have expected prefix.");
    get_parameter_context.result = execution_result;
    get_parameter_context.Finish();
    return execution_result;
  }

  // Example value: "BUYER_FRONTEND_PORT"
  const auto& flag = parameter_name.substr(prefix.size(), parameter_name.size() - prefix.size());

  // Get flag values from environment variables.
  // We need to consider adding prefix for environment variables to avoid collision.
  const char* value_from_env = std::getenv(flag.c_str());
  if (value_from_env) {
    get_parameter_context.response->set_parameter_value(value_from_env);
    get_parameter_context.result = SuccessExecutionResult();
    get_parameter_context.Finish();
    return SuccessExecutionResult();
  } else {
    auto execution_result = FailureExecutionResult(
        SC_AZURE_PARAMETER_CLIENT_PROVIDER_PARAMETER_NOT_FOUND);
    SCP_ERROR_CONTEXT(kAzureParameterClientProvider, get_parameter_context,
                      execution_result,
                      "Failed to get the parameter value for %s.",
                      get_parameter_context.request->parameter_name().c_str());
    get_parameter_context.result = execution_result;
    get_parameter_context.Finish();
    return execution_result;
  }
}


#ifndef TEST_CPIO
std::shared_ptr<ParameterClientProviderInterface>
ParameterClientProviderFactory::Create(
    const std::shared_ptr<ParameterClientOptions>& options,
    const std::shared_ptr<InstanceClientProviderInterface>&
        instance_client_provider,
    const std::shared_ptr<core::AsyncExecutorInterface>& cpu_async_executor,
    const std::shared_ptr<core::AsyncExecutorInterface>& io_async_executor) {
  return std::make_shared<AzureParameterClientProvider>();
}
#endif
}  // namespace google::scp::cpio::client_providers
