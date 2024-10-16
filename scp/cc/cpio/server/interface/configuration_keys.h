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

#ifndef CPIO_SERVER_INTERFACE_CONFIGURATION_KEYS_H_
#define CPIO_SERVER_INTERFACE_CONFIGURATION_KEYS_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "public/cpio/interface/type_def.h"

// Common configurations for all SDK services.
namespace google::scp::cpio {
// Optional. All options are listed in kLogOptionConfigMap. If not set, use the
// default value SysLog.
static constexpr char kSdkClientLogOption[] = "cmrt_sdk_log_option";

// Static duration map is heap allocated to avoid destructor call.
static const auto& kLogOptionConfigMap =
    *new absl::flat_hash_map<std::string, LogOption>{
        {"NoLog", LogOption::kNoLog},
        {"ConsoleLog", LogOption::kConsoleLog},
        {"SysLog", LogOption::kSysLog},
    };

}  // namespace google::scp::cpio

#endif  // CPIO_SERVER_INTERFACE_CONFIGURATION_KEYS_H_
