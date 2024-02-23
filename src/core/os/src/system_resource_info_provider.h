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

#ifndef CORE_OS_SRC_SYSTEM_RESOURCE_INFO_PROVIDER_H_
#define CORE_OS_SRC_SYSTEM_RESOURCE_INFO_PROVIDER_H_

#include <cstdint>

#include "src/public/core/interface/execution_result.h"

namespace google::scp::core::os::linux {
class SystemResourceInfoProvider {
 public:
  /**
   * @brief Get the Available Memory in KB
   *
   * @return The current memory available value or a failure if the value could
   * not be read.
   */
  virtual core::ExecutionResultOr<uint64_t> GetAvailableMemoryKb() noexcept = 0;
};
}  // namespace google::scp::core::os::linux

#endif  // CORE_OS_SRC_SYSTEM_RESOURCE_INFO_PROVIDER_H_
