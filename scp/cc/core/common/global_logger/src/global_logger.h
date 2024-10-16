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

#ifndef CORE_COMMON_GLOBAL_LOGGER_SRC_GLOBAL_LOGGER_H_
#define CORE_COMMON_GLOBAL_LOGGER_SRC_GLOBAL_LOGGER_H_

#include <cstdarg>
#include <memory>
#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "core/interface/errors.h"
#include "core/interface/logger_interface.h"

namespace google::scp::core::common {
class GlobalLogger {
 public:
  static const std::unique_ptr<core::LoggerInterface>& GetGlobalLogger();
  static bool IsLogLevelEnabled(const LogLevel log_level);
  static void SetGlobalLogLevels(absl::flat_hash_set<LogLevel> log_levels);
  static void SetGlobalLogger(std::unique_ptr<core::LoggerInterface> logger);
  static void ShutdownGlobalLogger();
};
}  // namespace google::scp::core::common

#define SCP_LOCATION absl::StrCat(__FILE__, ":", __func__, ":", __LINE__)

#define SCP_INFO(component_name, activity_id, message, ...)                  \
  __SCP_INFO_LOG(component_name, google::scp::core::common::kZeroUuid,       \
                 google::scp::core::common::kZeroUuid, activity_id, message, \
                 ##__VA_ARGS__)

#define SCP_INFO_CONTEXT(component_name, async_context, message, ...)         \
  __SCP_INFO_LOG(component_name, async_context.correlation_id,                \
                 async_context.parent_activity_id, async_context.activity_id, \
                 message, ##__VA_ARGS__)

#define __SCP_INFO_LOG(component_name, correlation_id, parent_activity_id, \
                       activity_id, message, ...)                          \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&        \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(          \
          google::scp::core::LogLevel::kInfo)) {                           \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Info(      \
        component_name, correlation_id, parent_activity_id, activity_id,   \
        SCP_LOCATION, message, ##__VA_ARGS__);                             \
  }

#define SCP_DEBUG(component_name, activity_id, message, ...)                  \
  __SCP_DEBUG_LOG(component_name, google::scp::core::common::kZeroUuid,       \
                  google::scp::core::common::kZeroUuid, activity_id, message, \
                  ##__VA_ARGS__)

#define SCP_DEBUG_CONTEXT(component_name, async_context, message, ...)         \
  __SCP_DEBUG_LOG(component_name, async_context.correlation_id,                \
                  async_context.parent_activity_id, async_context.activity_id, \
                  message, ##__VA_ARGS__)

#define __SCP_DEBUG_LOG(component_name, correlation_id, parent_activity_id, \
                        activity_id, message, ...)                          \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&         \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(           \
          google::scp::core::LogLevel::kDebug)) {                           \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Debug(      \
        component_name, correlation_id, parent_activity_id, activity_id,    \
        SCP_LOCATION, message, ##__VA_ARGS__);                              \
  }

#define SCP_WARNING(component_name, activity_id, message, ...)            \
  __SCP_WARNING_LOG(component_name, google::scp::core::common::kZeroUuid, \
                    google::scp::core::common::kZeroUuid, activity_id,    \
                    message, ##__VA_ARGS__)

#define SCP_WARNING_CONTEXT(component_name, async_context, message, ...) \
  __SCP_WARNING_LOG(component_name, async_context.correlation_id,        \
                    async_context.parent_activity_id,                    \
                    async_context.activity_id, message, ##__VA_ARGS__)

#define __SCP_WARNING_LOG(component_name, correlation_id, parent_activity_id, \
                          activity_id, message, ...)                          \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&           \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(             \
          google::scp::core::LogLevel::kWarning)) {                           \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Warning(      \
        component_name, correlation_id, parent_activity_id, activity_id,      \
        SCP_LOCATION, message, ##__VA_ARGS__);                                \
  }

#define SCP_ERROR(component_name, activity_id, execution_result, message, ...) \
  __SCP_ERROR_LOG(component_name, google::scp::core::common::kZeroUuid,        \
                  google::scp::core::common::kZeroUuid, activity_id,           \
                  execution_result, message, ##__VA_ARGS__)

#define SCP_ERROR_CONTEXT(component_name, async_context, execution_result,     \
                          message, ...)                                        \
  __SCP_ERROR_LOG(component_name, async_context.correlation_id,                \
                  async_context.parent_activity_id, async_context.activity_id, \
                  execution_result, message, ##__VA_ARGS__)

#define __SCP_ERROR_LOG(component_name, correlation_id, parent_activity_id, \
                        activity_id, execution_result, message, ...)        \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&         \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(           \
          google::scp::core::LogLevel::kError)) {                           \
    const auto message_with_error =                                         \
        absl::StrCat(message, " Failed with: ",                             \
                     google::scp::core::errors::GetErrorMessage(            \
                         execution_result.status_code));                    \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Error(      \
        component_name, correlation_id, parent_activity_id, activity_id,    \
        SCP_LOCATION, message_with_error, ##__VA_ARGS__);                   \
  }

#define SCP_CRITICAL(component_name, activity_id, execution_result, message, \
                     ...)                                                    \
  __SCP_CRITICAL_LOG(component_name, google::scp::core::common::kZeroUuid,   \
                     google::scp::core::common::kZeroUuid, activity_id,      \
                     execution_result, message, ##__VA_ARGS__)

#define SCP_CRITICAL_CONTEXT(component_name, async_context, execution_result, \
                             message, ...)                                    \
  __SCP_CRITICAL_LOG(component_name, async_context.correlation_id,            \
                     async_context.parent_activity_id,                        \
                     async_context.activity_id, execution_result, message,    \
                     ##__VA_ARGS__)

#define __SCP_CRITICAL_LOG(component_name, correlation_id, parent_activity_id, \
                           activity_id, execution_result, message, ...)        \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&            \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(              \
          google::scp::core::LogLevel::kCritical)) {                           \
    const auto message_with_error =                                            \
        absl::StrCat(message, " Failed with: ",                                \
                     google::scp::core::errors::GetErrorMessage(               \
                         execution_result.status_code));                       \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Critical(      \
        component_name, correlation_id, parent_activity_id, activity_id,       \
        SCP_LOCATION, message_with_error, ##__VA_ARGS__);                      \
  }

#define SCP_ALERT(component_name, activity_id, execution_result, message, ...) \
  __SCP_ALERT_LOG(component_name, google::scp::core::common::kZeroUuid,        \
                  google::scp::core::common::kZeroUuid, activity_id,           \
                  execution_result, message, ##__VA_ARGS__)

#define SCP_ALERT_CONTEXT(component_name, async_context, execution_result,     \
                          message, ...)                                        \
  __SCP_ALERT_LOG(component_name, async_context.correlation_id,                \
                  async_context.parent_activity_id, async_context.activity_id, \
                  execution_result, message, ##__VA_ARGS__)

#define __SCP_ALERT_LOG(component_name, correlation_id, parent_activity_id, \
                        activity_id, execution_result, message, ...)        \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&         \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(           \
          google::scp::core::LogLevel::kAlert)) {                           \
    const auto message_with_error =                                         \
        absl::StrCat(message, " Failed with: ",                             \
                     google::scp::core::errors::GetErrorMessage(            \
                         execution_result.status_code));                    \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Alert(      \
        component_name, correlation_id, parent_activity_id, activity_id,    \
        SCP_LOCATION, message_with_error, ##__VA_ARGS__);                   \
  }

#define SCP_EMERGENCY(component_name, activity_id, execution_result, message, \
                      ...)                                                    \
  __SCP_EMERGENCY_LOG(component_name, google::scp::core::common::kZeroUuid,   \
                      google::scp::core::common::kZeroUuid, activity_id,      \
                      execution_result, message, ##__VA_ARGS__)

#define SCP_EMERGENCY_CONTEXT(component_name, async_context, execution_result, \
                              message, ...)                                    \
  __SCP_EMERGENCY_LOG(component_name, async_context.correlation_id,            \
                      async_context.parent_activity_id,                        \
                      async_context.activity_id, execution_result, message,    \
                      ##__VA_ARGS__)

#define __SCP_EMERGENCY_LOG(component_name, correlation_id,                    \
                            parent_activity_id, activity_id, execution_result, \
                            message, ...)                                      \
  if (google::scp::core::common::GlobalLogger::GetGlobalLogger() &&            \
      google::scp::core::common::GlobalLogger::IsLogLevelEnabled(              \
          google::scp::core::LogLevel::kEmergency)) {                          \
    const auto message_with_error =                                            \
        absl::StrCat(message, " Failed with: ",                                \
                     google::scp::core::errors::GetErrorMessage(               \
                         execution_result.status_code));                       \
    google::scp::core::common::GlobalLogger::GetGlobalLogger()->Emergency(     \
        component_name, correlation_id, parent_activity_id, activity_id,       \
        SCP_LOCATION, message_with_error, ##__VA_ARGS__);                      \
  }

#endif  // CORE_COMMON_GLOBAL_LOGGER_SRC_GLOBAL_LOGGER_H_
