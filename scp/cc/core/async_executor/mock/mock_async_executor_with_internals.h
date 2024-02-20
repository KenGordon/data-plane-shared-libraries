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

#ifndef CORE_ASYNC_EXECUTOR_MOCK_MOCK_ASYNC_EXECUTOR_WITH_INTERNALS_H_
#define CORE_ASYNC_EXECUTOR_MOCK_MOCK_ASYNC_EXECUTOR_WITH_INTERNALS_H_

#include <atomic>
#include <functional>
#include <memory>
#include <utility>

#include "scp/cc/core/async_executor/src/async_executor.h"

namespace google::scp::core::async_executor::mock {
class MockAsyncExecutorWithInternals : public core::AsyncExecutor {
 public:
  MockAsyncExecutorWithInternals(size_t thread_count, size_t queue_cap)
      : core::AsyncExecutor(thread_count, queue_cap) {}

  ExecutionResult Schedule(AsyncOperation work,
                           AsyncPriority priority) noexcept override {
    if (schedule_pre_caller) {
      auto new_work = [&, work = std::move(work)]() mutable {
        if (schedule_pre_caller()) {
          work();
        }
      };

      return AsyncExecutor::Schedule(std::move(new_work), priority);
    }

    return AsyncExecutor::Schedule(std::move(work), priority);
  }

  ExecutionResult Schedule(
      AsyncOperation work, AsyncPriority priority,
      AsyncExecutorAffinitySetting affinity) noexcept override {
    if (schedule_pre_caller) {
      auto new_work = [&, work = std::move(work)]() mutable {
        if (schedule_pre_caller()) {
          work();
        }
      };

      return AsyncExecutor::Schedule(std::move(new_work), priority, affinity);
    }

    return AsyncExecutor::Schedule(std::move(work), priority, affinity);
  }

  ExecutionResult ScheduleFor(AsyncOperation work,
                              Timestamp timestamp) noexcept override {
    std::function<bool()> callback;
    return ScheduleFor(std::move(work), timestamp, callback);
  }

  ExecutionResult ScheduleFor(
      AsyncOperation work, Timestamp timestamp,
      AsyncExecutorAffinitySetting affinity) noexcept override {
    return ScheduleFor(std::move(work), timestamp, affinity);
  }

  ExecutionResult ScheduleFor(
      AsyncOperation work, Timestamp timestamp,
      std::function<bool()>& cancellation_callback) noexcept override {
    if (schedule_for_pre_caller) {
      auto new_work = [&, work = std::move(work)]() mutable {
        if (schedule_for_pre_caller()) {
          work();
        }
      };

      return AsyncExecutor::ScheduleFor(std::move(new_work), timestamp,
                                        cancellation_callback);
    }

    return AsyncExecutor::ScheduleFor(std::move(work), timestamp,
                                      cancellation_callback);
  }

  ExecutionResult ScheduleFor(
      AsyncOperation work, Timestamp timestamp,
      std::function<bool()>& cancellation_callback,
      AsyncExecutorAffinitySetting affinity) noexcept override {
    if (schedule_for_pre_caller) {
      auto new_work = [&, work = std::move(work)]() mutable {
        if (schedule_for_pre_caller()) {
          work();
        }
      };

      return AsyncExecutor::ScheduleFor(std::move(new_work), timestamp,
                                        cancellation_callback, affinity);
    }

    return AsyncExecutor::ScheduleFor(std::move(work), timestamp,
                                      cancellation_callback, affinity);
  }

  std::function<bool()> schedule_pre_caller;
  std::function<bool()> schedule_for_pre_caller;
};
}  // namespace google::scp::core::async_executor::mock

#endif  // CORE_ASYNC_EXECUTOR_MOCK_MOCK_ASYNC_EXECUTOR_WITH_INTERNALS_H_
