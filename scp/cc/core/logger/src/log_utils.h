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

#ifndef CORE_LOGGER_SRC_LOG_UTILS_H_
#define CORE_LOGGER_SRC_LOG_UTILS_H_

#include <string>

#include "core/logger/interface/log_provider_interface.h"

namespace google::scp::core::logger {

/// Returns a string representation for LogLevel
std::string ToString(const LogLevel& level);

LogLevel FromString(std::string_view level);

std::string operator+(const LogLevel& level, std::string_view text);

std::string operator+(std::string_view text, const LogLevel& level);

}  // namespace google::scp::core::logger

#endif  // CORE_LOGGER_SRC_LOG_UTILS_H_
