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

#ifndef ROMA_WORKER_SRC_EXECUTION_WATCHDOG_H_
#define ROMA_WORKER_SRC_EXECUTION_WATCHDOG_H_

#include <cstdlib>
#include <thread>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "core/interface/service_interface.h"
#include "core/interface/type_def.h"
#include "include/v8.h"
#include "public/core/interface/execution_result.h"
#include "src/cpp/util/duration.h"

using privacy_sandbox::server_common::ExpiringFlag;
using privacy_sandbox::server_common::SteadyClock;

namespace google::scp::roma::worker {
/**
 * @brief ExecutionWatchDog starts a thread that monitors the execution
 * time of each code object. If the code object execution time is over the
 * limit, ExecutionWatchDog will forcefully terminate v8 isolate.
 *
 */
class ExecutionWatchDog : public core::ServiceInterface {
 public:
  ExecutionWatchDog()
      : expiring_flag_(SteadyClock::RealClock()),
        is_terminate_called_(false),
        is_running_(false) {
    expiring_flag_.Set(absl::InfiniteDuration());
  }

  ~ExecutionWatchDog() { Stop(); }

  core::ExecutionResult Init() noexcept;
  // Run returns after the watchdog thread is up and running.
  core::ExecutionResult Run() noexcept;
  core::ExecutionResult Stop() noexcept;

  /**
   * @brief Start timing the execution in the input isolate. If the execution is
   * over time, the watchdog will terminate the execution in the isolate.
   *
   * @param isolate
   * @param ms_before_timeout
   */
  void StartTimer(v8::Isolate* isolate,
                  core::TimeDuration ms_before_timeout) noexcept;

  /// @brief End timing execution. This function will reset the
  /// timeout_timestamp_ to UINT64_MAX to avoid terminate standby isolate.
  void EndTimer() noexcept;

  bool IsTerminateCalled() noexcept;

 private:
  /// @brief Timer function running in ExecutionWatchDog thread.
  void WaitForTimeout() noexcept;

  /// @brief Used to track timeouts.
  ExpiringFlag expiring_flag_;

  /// @brief An instance of v8 isolate.
  v8::Isolate* v8_isolate_{nullptr};

  /// @brief Thread safety for Stop and StartTimer
  /// thread that Stop() or StartTimer() is called.
  absl::Mutex mutex_;

  absl::CondVar cv_;

  /// @brief thread state signal of ExecutionWatchDog.
  bool is_running_ ABSL_GUARDED_BY(mutex_);

  bool is_terminate_called_ ABSL_GUARDED_BY(mutex_);

  /// @brief ExecutionWatchDog thread.
  std::thread execution_watchdog_thread_;
};

}  // namespace google::scp::roma::worker

#endif  // ROMA_WORKER_SRC_EXECUTION_WATCHDOG_H_
