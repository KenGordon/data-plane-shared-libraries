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

#include "service_utils.h"

#include <execinfo.h>
#include <unistd.h>

#include <csignal>
#include <iostream>
#include <list>
#include <memory>
#include <string>

#include "absl/strings/str_cat.h"
#include "core/common/global_logger/src/global_logger.h"
#include "core/common/uuid/src/uuid.h"
#include "core/config_provider/src/env_config_provider.h"
#include "core/interface/config_provider_interface.h"
#include "core/interface/errors.h"
#include "core/interface/service_interface.h"
#include "core/logger/src/log_providers/console_log_provider.h"
#include "core/logger/src/log_providers/syslog/syslog_log_provider.h"
#include "core/logger/src/logger.h"
#include "core/network/src/grpc_network_service.h"
#include "cpio/client_providers/interface/cloud_initializer_interface.h"
#include "cpio/server/interface/configuration_keys.h"

using google::scp::core::ConfigProviderInterface;
using google::scp::core::EnvConfigProvider;
using google::scp::core::ExecutionResult;
using google::scp::core::GrpcNetworkService;
using google::scp::core::LoggerInterface;
using google::scp::core::NetworkServiceInterface;
using google::scp::core::ServiceInterface;
using google::scp::core::common::GlobalLogger;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::GetErrorMessage;
using google::scp::core::logger::ConsoleLogProvider;
using google::scp::core::logger::Logger;
using google::scp::core::logger::log_providers::SyslogLogProvider;
using google::scp::cpio::client_providers::CloudInitializerFactory;
using google::scp::cpio::client_providers::CloudInitializerInterface;

namespace google::scp::cpio {
void Init(const std::shared_ptr<ServiceInterface>& service,
          std::string_view service_name) {
  if (service) {
    auto execution_result = service->Init();
    if (!execution_result.Successful()) {
      SCP_ERROR(service_name, kZeroUuid, execution_result,
                "Failed to initialize the service.");
      throw std::runtime_error(
          absl::StrCat(service_name, " failed to initialized. ",
                       GetErrorMessage(execution_result.status_code)));
    }
    SCP_INFO(service_name, kZeroUuid, "Properly initialized the service.");
    std::cout << service_name << " initialized." << std::endl;
  }
}

void Run(const std::shared_ptr<ServiceInterface>& service,
         std::string_view service_name) {
  if (service) {
    auto execution_result = service->Run();
    if (!execution_result.Successful()) {
      SCP_ERROR(service_name, kZeroUuid, execution_result,
                "Failed to run the service.");
      throw std::runtime_error(
          absl::StrCat(service_name, " failed to run. ",
                       GetErrorMessage(execution_result.status_code)));
    }
    SCP_INFO(service_name, kZeroUuid, "Successfully running the service.");
    std::cout << service_name << " running." << std::endl;
  }
}

void Stop(const std::shared_ptr<ServiceInterface>& service,
          std::string_view service_name) {
  if (service) {
    auto execution_result = service->Stop();
    if (!execution_result.Successful()) {
      SCP_ERROR(service_name, kZeroUuid, execution_result,
                "Failed to stop the service.");
      throw std::runtime_error(
          absl::StrCat(service_name, " failed to stop. ",
                       GetErrorMessage(execution_result.status_code)));
    }
    SCP_INFO(service_name, kZeroUuid, "Properly stopped the service.");
    std::cout << service_name << " stopped." << std::endl;
  }
}

void RunLogger(
    const std::shared_ptr<ConfigProviderInterface>& config_provider) {
  LogOption log_option = LogOption::kSysLog;
  std::string log_option_config;
  if (TryReadConfigString(config_provider, kSdkClientLogOption,
                          log_option_config)
          .Successful()) {
    auto it = kLogOptionConfigMap.find(log_option_config);
    if (it == kLogOptionConfigMap.end()) {
      throw std::runtime_error("Invalid Log option.");
    }
    log_option = it->second;
  }

  std::unique_ptr<LoggerInterface> logger_ptr;
  switch (log_option) {
    case LogOption::kNoLog:
      break;
    case LogOption::kConsoleLog:
      logger_ptr =
          std::make_unique<Logger>(std::make_unique<ConsoleLogProvider>());
      break;
    case LogOption::kSysLog:
      logger_ptr =
          std::make_unique<Logger>(std::make_unique<SyslogLogProvider>());
      break;
  }
  if (logger_ptr) {
    if (!logger_ptr->Init().Successful()) {
      throw std::runtime_error("Cannot initialize logger.");
    }
    if (!logger_ptr->Run().Successful()) {
      throw std::runtime_error("Cannot run logger.");
    }
    GlobalLogger::SetGlobalLogger(std::move(logger_ptr));
    std::cout << "Logger running." << std::endl;
  }
}

void StopLogger() {
  if (GlobalLogger::GetGlobalLogger()) {
    auto execution_result = GlobalLogger::GetGlobalLogger()->Stop();
    if (!execution_result.Successful()) {
      throw std::runtime_error("Logger failed to stop.");
    }
    std::cout << "Logger stopped." << std::endl;
  }
}

void InitializeCloud(
    std::shared_ptr<CloudInitializerInterface>& cloud_initializer,
    std::string_view service_name) {
  cloud_initializer = CloudInitializerFactory::Create();
  Init(cloud_initializer, service_name);
  Run(cloud_initializer, service_name);
  cloud_initializer->InitCloud();
}

void ShutdownCloud(
    std::shared_ptr<CloudInitializerInterface>& cloud_initializer,
    std::string_view service_name) {
  cloud_initializer->ShutdownCloud();
  Stop(cloud_initializer, service_name);
}

void RunConfigProvider(
    std::shared_ptr<ConfigProviderInterface>& config_provider,
    std::string_view service_name) {
  config_provider = std::make_shared<EnvConfigProvider>();
  Init(config_provider, service_name);
  Run(config_provider, service_name);
}

void RunNetworkServer(
    std::shared_ptr<core::NetworkServiceInterface>& network_service,
    int32_t network_concurrency, std::string_view service_name,
    std::string_view server_uri) {
  network_service = std::make_shared<GrpcNetworkService>(
      GrpcNetworkService::AddressType::kUNIX, std::string{server_uri},
      network_concurrency);
  Init(network_service, service_name);
  Run(network_service, service_name);
}

void SignalSegmentationHandler(int signum) {
  const int max_addresses = 25;
  void* stack_lines[max_addresses];
  size_t printed_count;

  printed_count = backtrace(stack_lines, max_addresses);
  fprintf(stderr, "Signal received with code: %d:\n", signum);
  backtrace_symbols_fd(stack_lines, printed_count, STDERR_FILENO);
  exit(signum);
}

std::string ReadConfigString(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key) {
  std::string config_value;
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_value);
  if (!execution_result.Successful()) {
    throw std::runtime_error(
        absl::StrCat(config_key, " is not provided. ",
                     GetErrorMessage(execution_result.status_code)));
  }
  return config_value;
}

void ReadConfigStringList(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key, std::list<std::string>& config_values) {
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_values);
  if (!execution_result.Successful()) {
    throw std::runtime_error(
        absl::StrCat(config_key, " is not provided. ",
                     GetErrorMessage(execution_result.status_code)));
  }
}

ExecutionResult TryReadConfigStringList(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key, std::list<std::string>& config_values) {
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_values);
  if (!execution_result.Successful()) {
    std::cout << "Optional " << config_key << " is not provided. "
              << GetErrorMessage(execution_result.status_code) << std::endl;
  }
  return execution_result;
}

ExecutionResult TryReadConfigString(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key, std::string& config_value) {
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_value);
  if (!execution_result.Successful()) {
    std::cout << "Optional " << config_key << " is not provided. "
              << GetErrorMessage(execution_result.status_code) << std::endl;
  }
  return execution_result;
}

ExecutionResult TryReadConfigBool(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key, bool& config_value) {
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_value);
  if (!execution_result.Successful()) {
    std::cout << "Optional " << config_key << " is not provided. "
              << GetErrorMessage(execution_result.status_code) << std::endl;
  }
  return execution_result;
}

int32_t ReadConfigInt(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key) {
  int32_t config_value;
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_value);
  if (!execution_result.Successful()) {
    throw std::runtime_error(
        absl::StrCat(config_key, " is not provided. ",
                     GetErrorMessage(execution_result.status_code)));
  }
  return config_value;
}

ExecutionResult TryReadConfigInt(
    const std::shared_ptr<ConfigProviderInterface> config_provider,
    std::string_view config_key, int32_t& config_value) {
  auto execution_result =
      config_provider->Get(std::string{config_key}, config_value);
  if (!execution_result.Successful()) {
    std::cout << "Optional " << config_key << " is not provided. "
              << GetErrorMessage(execution_result.status_code) << std::endl;
  }
  return execution_result;
}
}  // namespace google::scp::cpio
