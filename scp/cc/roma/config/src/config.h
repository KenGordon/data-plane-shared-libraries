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

#ifndef ROMA_CONFIG_SRC_CONFIG_H_
#define ROMA_CONFIG_SRC_CONFIG_H_

#include <stddef.h>

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "function_binding_object_v2.h"

namespace google::scp::roma {

inline constexpr size_t kKB = 1024u;
inline constexpr size_t kMB = kKB * 1024;
inline constexpr std::string_view kRomaVlogLevel = "ROMA_VLOG_LEVEL";
inline constexpr size_t kDefaultBufferSizeInMb = 1;

struct JsEngineResourceConstraints {
  /**
   * @brief The initial heap size. If left as zero, the default value will be
   * used. By default, JS engine starts with a small heap and dynamically grows
   * it to match the set of live objects. This may lead to ineffective garbage
   * collections at startup if the live set is large. Setting the initial heap
   * size avoids such garbage collections.
   *
   */
  size_t initial_heap_size_in_mb = 0;

  /**
   * @brief The hard limit for the heap size. When the heap size approaches this
   * limit, JS engine will perform series of garbage collections. If garbage
   * collections do not help, the JS engine will crash with a fatal process out
   * of memory.
   *
   */
  size_t maximum_heap_size_in_mb = 0;
};

template <typename TMetadata = DefaultMetadata>
class Config {
 public:
  /**
   * @brief The number of workers that Roma will start. If no valid value is
   * configured here, the default number of workers (number of host CPUs) will
   * be started.
   *
   * NOTE: A valid value is [1, number_of_host_CPUs].
   */
  size_t number_of_workers = 0;

  /// @brief The size of worker queue, which caches the requests. Worker could
  /// process the item in the queue one by one. The default queue size is 100.
  size_t worker_queue_max_items = 0;

  /**
   * @brief The maximum number of pages that the WASM memory can use. Each page
   * is 64KiB. Will be clamped to 65536 (4GiB) if larger. If left at zero, the
   * default behavior is to use the maximum value allowed (up to 4GiB).
   *
   */
  size_t max_wasm_memory_number_of_pages = 0;

  /**
   * @brief Enable a memory check that will be performed upon initialization.
   * If not enough memory is available, the service will fail to start.
   *
   */
  bool enable_startup_memory_check = true;

  /**
   * @brief Function that can be set to overwrite the default memory check
   * threshold. If this function returns a value that is equal to or smaller
   * than the available system memory at the time of initialization, roma will
   * fail to init. The default memory computation uses values based on
   * the number of workers.
   * The value returned should be in KB.
   */
  std::function<uint64_t()> GetStartupMemoryCheckMinimumNeededValueKb;

  /**
   * @brief The maximum amount of VIRTUAL memory that the worker processes are
   * allowed to use. The worker process will be terminated if it exceeds this
   * size. If not provided, the default is that the process does not have a cap
   * on the virtual address space and will attempt to use up to the maximum
   * address space available.
   * NOTE: This setting maps directly to the Linux resource limit RLIMIT_AS.
   * https://linux.die.net/man/2/setrlimit
   */
  size_t max_worker_virtual_memory_mb = 0;

  /**
   * @brief The number of code versions to cache. This determines how many code
   * version are available to execute after being loaded. This is used for an
   * LRU cache and if additional code versions are cached, the LRU one will be
   * replaced.
   *
   */
  size_t code_version_cache_size = 5;

  /**
   * @brief The sandbox data shared buffer provides a shared memory for sharing
   * request and response data between the roma host binary and sandboxee. The
   * default size of the buffer is 1MB, but you can increase the size if needed
   * to hold the largest request or response data that you expect to share.
   *
   */
  size_t sandbox_request_response_shared_buffer_size_mb = 0;

  /**
   * @brief The flag that allows the sandbox to communicate only with the
   * buffer. Roma performs better when the sandbox communicates with the buffer
   * only. However, since the buffer is a pre-allocated memory space when the
   * Roma is initialized, the client needs to know the upper bound of the
   * data payload that is shared between the sandbox and the buffer. If the size
   * of the data payload is greater than the size of the buffer, Roma will
   * return an oversize error.
   *
   */
  bool enable_sandbox_sharing_request_response_with_buffer_only = false;

  using FunctionBindingObjectPtr =
      std::shared_ptr<FunctionBindingObjectV2<TMetadata>>;

  /**
   * @brief Register a function binding v2 object. Only supported with the
   * sandboxed service.
   *
   * @param function_binding
   */
  void RegisterFunctionBinding(
      std::unique_ptr<FunctionBindingObjectV2<TMetadata>> function_binding) {
    function_bindings_v2_.emplace_back(function_binding.get());
    function_binding.release();
  }

  std::vector<FunctionBindingObjectPtr> GetFunctionBindings() const {
    return std::vector<FunctionBindingObjectPtr>(function_bindings_v2_.begin(),
                                                 function_bindings_v2_.end());
  }

  /**
   * Configures the constraints with reasonable default values based on the
   * provided heap size limit. `initial_heap_size_in_bytes` should be smaller
   * than `maximum_heap_size_in_bytes`.
   *
   * \param initial_heap_size_in_bytes The initial heap size or zero.
   * \param maximum_heap_size_in_bytes The hard limit for the heap size.
   */
  void ConfigureJsEngineResourceConstraints(size_t initial_heap_size_in_mb,
                                            size_t maximum_heap_size_in_mb) {
    js_engine_resource_constraints_.initial_heap_size_in_mb =
        initial_heap_size_in_mb;
    js_engine_resource_constraints_.maximum_heap_size_in_mb =
        maximum_heap_size_in_mb;
  }

  /**
   * @brief Get JS engine resource constraints objects
   *
   * @param[out] js_engine_resource_constraints
   */
  void GetJsEngineResourceConstraints(
      JsEngineResourceConstraints& js_engine_resource_constraints) const {
    js_engine_resource_constraints = js_engine_resource_constraints_;
  }

 private:
  /**
   * @brief User-registered function JS/C++ function bindings
   */
  std::vector<FunctionBindingObjectPtr> function_bindings_v2_;

  /// v8 heap resource constraints.
  JsEngineResourceConstraints js_engine_resource_constraints_;
};
}  // namespace google::scp::roma

#endif  // ROMA_CONFIG_SRC_CONFIG_H_
