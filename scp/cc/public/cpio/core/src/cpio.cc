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

#include "scp/cc/public/cpio/interface/cpio.h"

#include <memory>
#include <utility>

#include "scp/cc/core/common/global_logger/src/global_logger.h"
#include "scp/cc/core/logger/interface/log_provider_interface.h"
#include "scp/cc/core/logger/src/log_providers/console_log_provider.h"
#include "scp/cc/core/logger/src/log_providers/syslog/syslog_log_provider.h"
#include "scp/cc/cpio/client_providers/global_cpio/src/global_cpio.h"
#include "scp/cc/cpio/client_providers/interface/cpio_provider_interface.h"
#include "scp/cc/public/core/interface/execution_result.h"
#include "scp/cc/public/cpio/interface/type_def.h"

#include "cpio_utils.h"

using google::scp::core::ExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::logger::ConsoleLogProvider;
using google::scp::core::logger::LogProviderInterface;
using google::scp::core::logger::log_providers::SyslogLogProvider;
using google::scp::cpio::CpioOptions;
using google::scp::cpio::LogOption;
using google::scp::cpio::client_providers::CpioProviderFactory;
using google::scp::cpio::client_providers::CpioProviderInterface;
using google::scp::cpio::client_providers::GlobalCpio;

namespace google::scp::cpio {

#ifndef TEST_CPIO
static ExecutionResult SetGlobalCpio(const CpioOptions& options) {
  cpio_ptr = CpioProviderFactory::Create(options);
  CpioUtils::RunAndSetGlobalCpio(std::move(cpio_ptr));
  return SuccessExecutionResult();
}
#endif

ExecutionResult Cpio::InitCpio(CpioOptions options) {
  InitializeCpioLog(options.log_option);
#ifdef TEST_CPIO
  return SuccessExecutionResult();
#else
  return SetGlobalCpio(options);
#endif
}

ExecutionResult Cpio::ShutdownCpio(CpioOptions options) {
  if (GlobalCpio::GetGlobalCpio()) {
    auto execution_result = GlobalCpio::GetGlobalCpio()->Stop();
    if (!execution_result.Successful()) {
      return execution_result;
    }
    GlobalCpio::ShutdownGlobalCpio();
  }

  return SuccessExecutionResult();
}

}  // namespace google::scp::cpio
