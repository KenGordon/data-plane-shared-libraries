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

#include "worker_utils.h"

#include <unistd.h>

#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/numbers.h"

#include "error_codes.h"

using google::scp::core::ExecutionResult;
using google::scp::core::ExecutionResultOr;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::errors::SC_ROMA_WORKER_MISSING_METADATA_ITEM;
using google::scp::core::errors::SC_ROMA_WORKER_STR_CONVERT_INT_FAIL;

namespace google::scp::roma::sandbox::worker {

ExecutionResultOr<std::string_view> WorkerUtils::GetValueFromMetadata(
    const absl::flat_hash_map<std::string_view, std::string_view>& metadata,
    std::string_view key) noexcept {
  if (const auto& it = metadata.find(key); it != metadata.end()) {
    return it->second;
  }
  return FailureExecutionResult(SC_ROMA_WORKER_MISSING_METADATA_ITEM);
}

}  // namespace google::scp::roma::sandbox::worker
