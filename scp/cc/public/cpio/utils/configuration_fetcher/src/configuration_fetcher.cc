/*
 * Copyright 2023 Google LLC
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

#include "configuration_fetcher.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "absl/functional/bind_front.h"
#include "absl/strings/str_cat.h"
#include "core/interface/async_context.h"
#include "core/interface/async_executor_interface.h"
#include "cpio/server/interface/configuration_keys.h"
#include "cpio/server/interface/crypto_service/configuration_keys.h"
#include "cpio/server/interface/queue_service/configuration_keys.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/type_def.h"
#include "public/cpio/proto/crypto_service/v1/crypto_service.pb.h"
#include "public/cpio/proto/instance_service/v1/instance_service.pb.h"
#include "public/cpio/proto/parameter_service/v1/parameter_service.pb.h"
#include "public/cpio/utils/configuration_fetcher/interface/configuration_keys.h"
#include "public/cpio/utils/sync_utils/sync_utils.h"
#include "scp/cc/core/common/uuid/src/uuid.h"

#include "configuration_fetcher_utils.h"
#include "error_codes.h"

using google::cmrt::sdk::crypto_service::v1::HpkeAead;
using google::cmrt::sdk::crypto_service::v1::HpkeKdf;
using google::cmrt::sdk::crypto_service::v1::HpkeKem;
using google::cmrt::sdk::instance_service::v1::
    GetCurrentInstanceResourceNameRequest;
using google::cmrt::sdk::instance_service::v1::
    GetCurrentInstanceResourceNameResponse;
using google::cmrt::sdk::instance_service::v1::
    GetInstanceDetailsByResourceNameRequest;
using google::cmrt::sdk::instance_service::v1::
    GetInstanceDetailsByResourceNameResponse;
using google::cmrt::sdk::parameter_service::v1::GetParameterRequest;
using google::cmrt::sdk::parameter_service::v1::GetParameterResponse;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::ExecutionResultOr;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::SC_CONFIGURATION_FETCHER_CONVERSION_FAILED;
using google::scp::core::errors::
    SC_CONFIGURATION_FETCHER_ENVIRONMENT_NAME_NOT_FOUND;

namespace {
constexpr char kConfigurationFetcher[] = "ConfigurationFetcher";
constexpr char kEnvNameTag[] = "environment-name";
}  // namespace

namespace google::scp::cpio {
ExecutionResultOr<std::string> ConfigurationFetcher::GetParameterByName(
    std::string parameter_name) noexcept {
  std::string parameter;
  auto execution_result = SyncUtils::AsyncToSync<std::string, std::string>(
      absl::bind_front(&ConfigurationFetcher::GetParameterByNameAsync, this),
      parameter_name, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetParameterByName for %s.",
                            parameter_name.c_str());
  return parameter;
}

ExecutionResult ConfigurationFetcher::GetParameterByNameAsync(
    AsyncContext<std::string, std::string> context) noexcept {
  return GetConfiguration(context);
}

ExecutionResultOr<LogOption> ConfigurationFetcher::GetSharedLogOption(
    GetConfigurationRequest request) noexcept {
  LogOption parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, LogOption>(
          absl::bind_front(&ConfigurationFetcher::GetSharedLogOptionAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetSharedLogOption %s.",
                            kSdkClientLogOption);
  return parameter;
}

core::ExecutionResult ConfigurationFetcher::GetSharedLogOptionAsync(
    AsyncContext<GetConfigurationRequest, LogOption> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<LogOption>(
          kSdkClientLogOption, context,
          std::bind(ConfigurationFetcherUtils::StringToEnum<LogOption>,
                    std::placeholders::_1, kLogOptionConfigMap));
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<size_t> ConfigurationFetcher::GetSharedCpuThreadCount(
    GetConfigurationRequest request) noexcept {
  size_t parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, size_t>(
          absl::bind_front(&ConfigurationFetcher::GetSharedCpuThreadCountAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetSharedCpuThreadCount %s.",
                            kSharedCpuThreadCount);
  return parameter;
}

ExecutionResult ConfigurationFetcher::GetSharedCpuThreadCountAsync(
    AsyncContext<GetConfigurationRequest, size_t> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<size_t>(
          kSharedCpuThreadCount, context,
          absl::bind_front(ConfigurationFetcherUtils::StringToUInt<size_t>));
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<size_t> ConfigurationFetcher::GetSharedCpuThreadPoolQueueCap(
    GetConfigurationRequest request) noexcept {
  size_t parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, size_t>(
          absl::bind_front(
              &ConfigurationFetcher::GetSharedCpuThreadPoolQueueCapAsync, this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetSharedCpuThreadPoolQueueCap %s.",
                            kSharedCpuThreadCount);
  return parameter;
}

ExecutionResult ConfigurationFetcher::GetSharedCpuThreadPoolQueueCapAsync(
    AsyncContext<GetConfigurationRequest, size_t> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<size_t>(
          kSharedCpuThreadPoolQueueCap, context,
          absl::bind_front(ConfigurationFetcherUtils::StringToUInt<size_t>));
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<size_t> ConfigurationFetcher::GetSharedIoThreadCount(
    GetConfigurationRequest request) noexcept {
  size_t parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, size_t>(
          absl::bind_front(&ConfigurationFetcher::GetSharedIoThreadCountAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetSharedIoThreadCount %s.",
                            kSharedIoThreadCount);
  return parameter;
}

ExecutionResult ConfigurationFetcher::GetSharedIoThreadCountAsync(
    AsyncContext<GetConfigurationRequest, size_t> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<size_t>(
          kSharedIoThreadCount, context,
          absl::bind_front(ConfigurationFetcherUtils::StringToUInt<size_t>));
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<size_t> ConfigurationFetcher::GetSharedIoThreadPoolQueueCap(
    GetConfigurationRequest request) noexcept {
  size_t parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, size_t>(
          absl::bind_front(
              &ConfigurationFetcher::GetSharedIoThreadPoolQueueCapAsync, this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetSharedIoThreadPoolQueueCap %s.",
                            kSharedIoThreadCount);
  return parameter;
}

ExecutionResult ConfigurationFetcher::GetSharedIoThreadPoolQueueCapAsync(
    AsyncContext<GetConfigurationRequest, size_t> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<size_t>(
          kSharedIoThreadPoolQueueCap, context,
          ConfigurationFetcherUtils::StringToUInt<size_t>);
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<std::string> ConfigurationFetcher::GetQueueClientQueueName(
    GetConfigurationRequest request) noexcept {
  std::string parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, std::string>(
          absl::bind_front(&ConfigurationFetcher::GetQueueClientQueueNameAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetQueueClientQueueName %s.",
                            kQueueClientQueueName);
  return parameter;
}

core::ExecutionResult ConfigurationFetcher::GetQueueClientQueueNameAsync(
    AsyncContext<GetConfigurationRequest, std::string> context) noexcept {
  auto context_with_parameter_name =
      ContextConvertCallback(kQueueClientQueueName, context);
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<HpkeKem> ConfigurationFetcher::GetCryptoClientHpkeKem(
    GetConfigurationRequest request) noexcept {
  HpkeKem parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, HpkeKem>(
          absl::bind_front(&ConfigurationFetcher::GetCryptoClientHpkeKemAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetCryptoClientHpkeKem %s.",
                            kCryptoClientHpkeKem);
  return parameter;
}

core::ExecutionResult ConfigurationFetcher::GetCryptoClientHpkeKemAsync(
    AsyncContext<GetConfigurationRequest, HpkeKem> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<HpkeKem>(
          kCryptoClientHpkeKem, context,
          std::bind(ConfigurationFetcherUtils::StringToEnum<HpkeKem>,
                    std::placeholders::_1, kHpkeKemConfigMap));
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<HpkeKdf> ConfigurationFetcher::GetCryptoClientHpkeKdf(
    GetConfigurationRequest request) noexcept {
  HpkeKdf parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, HpkeKdf>(
          absl::bind_front(&ConfigurationFetcher::GetCryptoClientHpkeKdfAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetCryptoClientHpkeKdf %s.",
                            kCryptoClientHpkeKdf);
  return parameter;
}

core::ExecutionResult ConfigurationFetcher::GetCryptoClientHpkeKdfAsync(
    AsyncContext<GetConfigurationRequest, HpkeKdf> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<HpkeKdf>(
          kCryptoClientHpkeKdf, context,
          std::bind(ConfigurationFetcherUtils::StringToEnum<HpkeKdf>,
                    std::placeholders::_1, kHpkeKdfConfigMap));
  return GetConfiguration(context_with_parameter_name);
}

ExecutionResultOr<HpkeAead> ConfigurationFetcher::GetCryptoClientHpkeAead(
    GetConfigurationRequest request) noexcept {
  HpkeAead parameter;
  auto execution_result =
      SyncUtils::AsyncToSync<GetConfigurationRequest, HpkeAead>(
          absl::bind_front(&ConfigurationFetcher::GetCryptoClientHpkeAeadAsync,
                           this),
          request, parameter);
  RETURN_AND_LOG_IF_FAILURE(execution_result, kConfigurationFetcher, kZeroUuid,
                            "Failed to GetCryptoClientHpkeAead %s.",
                            kCryptoClientHpkeAead);
  return parameter;
}

core::ExecutionResult ConfigurationFetcher::GetCryptoClientHpkeAeadAsync(
    AsyncContext<GetConfigurationRequest, HpkeAead> context) noexcept {
  auto context_with_parameter_name =
      ConfigurationFetcherUtils::ContextConvertCallback<HpkeAead>(
          kCryptoClientHpkeAead, context,
          std::bind(ConfigurationFetcherUtils::StringToEnum<HpkeAead>,
                    std::placeholders::_1, kHpkeAeadConfigMap));
  return GetConfiguration(context_with_parameter_name);
}

AsyncContext<std::string, std::string>
ConfigurationFetcher::ContextConvertCallback(
    const std::string& parameter_name,
    AsyncContext<GetConfigurationRequest, std::string>&
        context_without_parameter_name) noexcept {
  return ConfigurationFetcherUtils::ContextConvertCallback<std::string>(
      parameter_name, context_without_parameter_name,
      [](const std::string& value) { return value; });
}

core::ExecutionResult ConfigurationFetcher::GetConfiguration(
    AsyncContext<std::string, std::string>&
        get_configuration_context) noexcept {
  return instance_client_->GetCurrentInstanceResourceName(
      GetCurrentInstanceResourceNameRequest(),
      std::bind(&ConfigurationFetcher::GetCurrentInstanceResourceNameCallback,
                this, std::placeholders::_1, std::placeholders::_2,
                get_configuration_context));
}

void ConfigurationFetcher::GetCurrentInstanceResourceNameCallback(
    const ExecutionResult& result,
    GetCurrentInstanceResourceNameResponse response,
    AsyncContext<std::string, std::string>&
        get_configuration_context) noexcept {
  if (!result.Successful()) {
    get_configuration_context.result = result;
    SCP_ERROR_CONTEXT(kConfigurationFetcher, get_configuration_context, result,
                      "Failed to GetCurrentInstanceResourceName");
    get_configuration_context.Finish();
    return;
  }

  GetInstanceDetailsByResourceNameRequest request;
  request.set_instance_resource_name(response.instance_resource_name());
  if (auto result = instance_client_->GetInstanceDetailsByResourceName(
          std::move(request),
          std::bind(
              &ConfigurationFetcher::GetInstanceDetailsByResourceNameCallback,
              this, std::placeholders::_1, std::placeholders::_2, response,
              get_configuration_context));
      !result.Successful()) {
    get_configuration_context.result = result;
    SCP_ERROR_CONTEXT(
        kConfigurationFetcher, get_configuration_context, result,
        "Failed to GetInstanceDetailsByResourceName for instance %s",
        response.instance_resource_name().c_str());
    get_configuration_context.Finish();
  }
}

void ConfigurationFetcher::GetInstanceDetailsByResourceNameCallback(
    const ExecutionResult& result,
    GetInstanceDetailsByResourceNameResponse get_instance_details_response,
    const GetCurrentInstanceResourceNameResponse& get_current_instance_response,
    AsyncContext<std::string, std::string>&
        get_configuration_context) noexcept {
  if (!result.Successful()) {
    get_configuration_context.result = result;
    SCP_ERROR_CONTEXT(
        kConfigurationFetcher, get_configuration_context, result,
        "Failed to GetInstanceDetailsByResourceName for instance %s",
        get_current_instance_response.instance_resource_name().c_str());
    get_configuration_context.Finish();
    return;
  }

  auto it = get_instance_details_response.instance_details().labels().find(
      std::string(kEnvNameTag));
  if (it == get_instance_details_response.instance_details().labels().end()) {
    get_configuration_context.result = FailureExecutionResult(
        SC_CONFIGURATION_FETCHER_ENVIRONMENT_NAME_NOT_FOUND);
    SCP_ERROR_CONTEXT(
        kConfigurationFetcher, get_configuration_context,
        get_configuration_context.result,
        "Failed to find environment name for instance %s",
        get_current_instance_response.instance_resource_name().c_str());
    get_configuration_context.Finish();
    return;
  }

  GetParameterRequest request;
  request.set_parameter_name(absl::StrCat("scp-", it->second, "-",
                                          *get_configuration_context.request));
  if (auto result = parameter_client_->GetParameter(
          std::move(request),
          std::bind(&ConfigurationFetcher::GetParameterCallback, this,
                    std::placeholders::_1, std::placeholders::_2,
                    get_configuration_context));
      !result.Successful()) {
    get_configuration_context.result = result;
    SCP_ERROR_CONTEXT(kConfigurationFetcher, get_configuration_context,
                      get_configuration_context.result,
                      "Failed to get parameter value for %s",
                      get_configuration_context.request->c_str());
    get_configuration_context.Finish();
  }
}

void ConfigurationFetcher::GetParameterCallback(
    const ExecutionResult& result, GetParameterResponse response,
    AsyncContext<std::string, std::string>&
        get_configuration_context) noexcept {
  if (!result.Successful()) {
    get_configuration_context.result = result;
    SCP_ERROR_CONTEXT(kConfigurationFetcher, get_configuration_context,
                      get_configuration_context.result,
                      "Failed to get parameter value for %s",
                      get_configuration_context.request->c_str());
    get_configuration_context.Finish();
    return;
  }

  get_configuration_context.result = SuccessExecutionResult();
  get_configuration_context.response =
      std::make_shared<std::string>(std::move(response.parameter_value()));
  get_configuration_context.Finish();
}
}  // namespace google::scp::cpio
