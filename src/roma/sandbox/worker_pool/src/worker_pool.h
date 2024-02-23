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

#ifndef ROMA_SANDBOX_WORKER_POOL_SRC_WORKER_POOL_H_
#define ROMA_SANDBOX_WORKER_POOL_SRC_WORKER_POOL_H_

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/roma/sandbox/worker_api/src/worker_api.h"

namespace google::scp::roma::sandbox::worker_pool {
class WorkerPool {
 public:
  /**
   * @brief Get the Pool Size
   *
   * @return size_t
   */
  virtual absl::Status Init() = 0;
  virtual absl::Status Run() = 0;
  virtual absl::Status Stop() = 0;

  virtual size_t GetPoolSize() = 0;

  /**
   * @brief Get a worker by index. Will return failure if bad index.
   *
   * @param index
   * @return absl::StatusOr<worker_api::WorkerApi*>
   */
  virtual absl::StatusOr<worker_api::WorkerApi*> GetWorker(size_t index) = 0;
};
}  // namespace google::scp::roma::sandbox::worker_pool

#endif  // ROMA_SANDBOX_WORKER_POOL_SRC_WORKER_POOL_H_
