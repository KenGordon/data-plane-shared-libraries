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

#ifndef ROMA_SANDBOX_WORKER_SRC_WORKER_H_
#define ROMA_SANDBOX_WORKER_SRC_WORKER_H_

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/span.h"
#include "core/common/lru_cache/src/lru_cache.h"
#include "core/interface/service_interface.h"
#include "public/core/interface/execution_result.h"
#include "roma/sandbox/js_engine/src/js_engine.h"

#include "error_codes.h"

namespace google::scp::roma::sandbox::worker {
/// @brief This class acts a single-threaded worker which receives work items
/// and executes them inside of a JS/WASM engine.
class Worker {
 public:
  explicit Worker(std::unique_ptr<js_engine::JsEngine> js_engine,
                  bool require_preload = true,
                  size_t compilation_context_cache_size = 5);

  core::ExecutionResult Run() noexcept;

  core::ExecutionResult Stop() noexcept;

  /**
   * @brief Run code object with an internal JS/WASM engine.
   *
   * @param code The code to compile and run
   * @param input The input to pass to the code
   * @param metadata The metadata associated with the code request
   * @param wasm The wasm code module needed to run the code
   * @return core::ExecutionResultOr<std::string>
   */
  virtual core::ExecutionResultOr<js_engine::ExecutionResponse> RunCode(
      std::string_view code, const std::vector<absl::string_view>& input,
      const absl::flat_hash_map<std::string_view, std::string_view>& metadata,
      absl::Span<const uint8_t> wasm) ABSL_LOCKS_EXCLUDED(cache_mu_);

 private:
  std::unique_ptr<js_engine::JsEngine> js_engine_;
  bool require_preload_;
  /**
   * @brief Used to keep track of compilation contexts
   *
   */
  absl::Mutex cache_mu_;
  core::common::LruCache<std::string, js_engine::RomaJsEngineCompilationContext>
      compilation_contexts_ ABSL_GUARDED_BY(cache_mu_);
};
}  // namespace google::scp::roma::sandbox::worker

#endif  // ROMA_SANDBOX_WORKER_SRC_WORKER_H_
