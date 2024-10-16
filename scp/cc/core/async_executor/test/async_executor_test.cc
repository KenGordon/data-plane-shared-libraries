// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "core/async_executor/src/async_executor.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/blocking_counter.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "core/async_executor/mock/mock_async_executor_with_internals.h"
#include "core/async_executor/src/error_codes.h"
#include "core/async_executor/src/typedef.h"
#include "core/interface/async_context.h"
#include "core/interface/async_executor_interface.h"
#include "core/test/test_config.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"

using google::scp::core::async_executor::mock::MockAsyncExecutorWithInternals;

namespace google::scp::core::test {

TEST(AsyncExecutorTests, CannotInitWithZeroThreadCount) {
  AsyncExecutor executor(0, 10);
  EXPECT_THAT(executor.Init(),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_INVALID_THREAD_COUNT)));
}

TEST(AsyncExecutorTests, CannotInitWithTooBigThreadCount) {
  AsyncExecutor executor(10001, 10);
  EXPECT_THAT(executor.Init(),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_INVALID_THREAD_COUNT)));
}

TEST(AsyncExecutorTests, CannotInitWithTooBigQueueCap) {
  AsyncExecutor executor(10, kMaxQueueCap + 1);
  EXPECT_THAT(executor.Init(),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_INVALID_QUEUE_CAP)));
}

TEST(AsyncExecutorTests, EmptyWorkQueue) {
  AsyncExecutor executor(1, 10);
  ASSERT_SUCCESS(executor.Init());
  ASSERT_SUCCESS(executor.Run());
  EXPECT_SUCCESS(executor.Stop());
}

TEST(AsyncExecutorTests, CannotRunTwice) {
  AsyncExecutor executor(1, 10);
  ASSERT_SUCCESS(executor.Init());
  ASSERT_SUCCESS(executor.Run());
  EXPECT_THAT(executor.Run(), ResultIs(FailureExecutionResult(
                                  errors::SC_ASYNC_EXECUTOR_ALREADY_RUNNING)));
  EXPECT_SUCCESS(executor.Stop());
}

TEST(AsyncExecutorTests, CannotStopTwice) {
  AsyncExecutor executor(1, 10);
  ASSERT_SUCCESS(executor.Init());
  ASSERT_SUCCESS(executor.Run());
  ASSERT_SUCCESS(executor.Stop());
  EXPECT_THAT(
      executor.Stop(),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(AsyncExecutorTests, CannotScheduleWorkBeforeInit) {
  AsyncExecutor executor(1, 10);
  EXPECT_THAT(executor.Schedule([] {}, AsyncPriority::Normal),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_NOT_INITIALIZED)));
  EXPECT_THAT(executor.ScheduleFor([] {}, 10000),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_NOT_INITIALIZED)));
}

TEST(AsyncExecutorTests, CannotScheduleWorkBeforeRun) {
  AsyncExecutor executor(1, 10);
  ASSERT_SUCCESS(executor.Init());
  EXPECT_THAT(
      executor.Schedule([] {}, AsyncPriority::Normal),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
  EXPECT_THAT(
      executor.ScheduleFor([] {}, 1000),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(AsyncExecutorTests, CannotRunBeforeInit) {
  AsyncExecutor executor(1, 10);
  EXPECT_THAT(executor.Run(), ResultIs(FailureExecutionResult(
                                  errors::SC_ASYNC_EXECUTOR_NOT_INITIALIZED)));
}

TEST(AsyncExecutorTests, CannotStopBeforeRun) {
  AsyncExecutor executor(1, 10);
  ASSERT_SUCCESS(executor.Init());
  EXPECT_THAT(
      executor.Stop(),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(AsyncExecutorTests, ExceedingQueueCapSchedule) {
  constexpr int kQueueCap = 1;
  MockAsyncExecutorWithInternals executor(1, kQueueCap);
  executor.Init();
  executor.Run();

  {
    // Blocking queue with enough work
    executor.Schedule(
        [&] { std::this_thread::sleep_for(std::chrono::seconds(5)); },
        AsyncPriority::Normal);

    // try to push more than the queue can handle
    auto start_time = std::chrono::high_resolution_clock::now();
    while (true) {
      auto result = executor.Schedule([&] {}, AsyncPriority::Normal);

      if (result ==
          RetryExecutionResult(errors::SC_ASYNC_EXECUTOR_EXCEEDING_QUEUE_CAP)) {
        break;
      }

      auto end_time = std::chrono::high_resolution_clock::now();
      auto diff = end_time - start_time;
      if (diff > std::chrono::seconds(5)) {
        FAIL() << "Queue cap schedule was never exceeded.";
      }
    }
  }

  {
    AsyncTask task;
    auto two_seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::seconds(2))
                           .count();

    auto schedule_for_timestamp = task.GetExecutionTimestamp() + two_seconds;
    executor.ScheduleFor([&] {}, schedule_for_timestamp);
    auto result = executor.ScheduleFor([&] {}, task.GetExecutionTimestamp());
    EXPECT_THAT(result, ResultIs(RetryExecutionResult(
                            errors::SC_ASYNC_EXECUTOR_EXCEEDING_QUEUE_CAP)));
  }

  executor.Stop();
}

TEST(AsyncExecutorTests, CountWorkSingleThread) {
  constexpr int kQueueCap = 10;
  AsyncExecutor executor(1, kQueueCap);
  executor.Init();
  executor.Run();
  {
    absl::BlockingCounter count(kQueueCap);
    for (int i = 0; i < kQueueCap; i++) {
      executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::Normal);
    }
    // Waits some time to finish the work.
    count.Wait();
  }
  {
    absl::BlockingCounter count(kQueueCap);
    for (int i = 0; i < kQueueCap; i++) {
      executor.ScheduleFor([&] { count.DecrementCount(); }, 123456);
    }
    // Waits some time to finish the work.
    count.Wait();
  }
  executor.Stop();
}

TEST(AsyncExecutorTests, CountWorkSingleThreadWithAffinity) {
  constexpr int kQueueCap = 10;
  AsyncExecutor executor(1, kQueueCap);
  executor.Init();
  executor.Run();
  absl::BlockingCounter count(kQueueCap);
  for (int i = 0; i < kQueueCap / 2; i++) {
    executor.Schedule(
        [&] {
          auto thread_id = std::this_thread::get_id();
          count.DecrementCount();
          // Schedule another increment - test the affinitized path with
          // matching thread IDs.
          executor.Schedule(
              [&count, thread_id = thread_id] {
                // The chosen thread ID should be the same as the calling one.
                EXPECT_EQ(std::this_thread::get_id(), thread_id);
                count.DecrementCount();
              },
              AsyncPriority::Normal,
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
        },
        AsyncPriority::Normal,
        AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
  }
  // Waits some time to finish the work.
  count.Wait();
  executor.Stop();
}

TEST(AsyncExecutorTests, CountWorkSingleThreadScheduleForWithAffinity) {
  constexpr int kQueueCap = 10;
  AsyncExecutor executor(1, kQueueCap);
  ASSERT_SUCCESS(executor.Init());
  ASSERT_SUCCESS(executor.Run());
  absl::BlockingCounter count(kQueueCap);
  for (int i = 0; i < kQueueCap / 2; i++) {
    executor.ScheduleFor(
        [&] {
          auto thread_id = std::this_thread::get_id();
          count.DecrementCount();
          // Schedule another incrementation - test the affinitized path with
          // matching thread IDs.
          executor.ScheduleFor(
              [&count, thread_id = thread_id] {
                // The chosen thread ID should be the same as the calling one.
                EXPECT_EQ(std::this_thread::get_id(), thread_id);
                count.DecrementCount();
              },
              123456,
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
        },
        123456,
        AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
  }
  // Waits some time to finish the work.
  count.Wait();
  executor.Stop();
}

TEST(AsyncExecutorTests, CountWorkSingleThreadNormalToUrgent) {
  constexpr int kQueueCap = 10;
  AsyncExecutor executor(1, kQueueCap);
  ASSERT_SUCCESS(executor.Init());
  ASSERT_SUCCESS(executor.Run());
  absl::BlockingCounter count(kQueueCap);
  for (int i = 0; i < kQueueCap / 2; i++) {
    executor.Schedule(
        [&] {
          count.DecrementCount();
          // Schedule another incrementation - test the affinitized path with
          // matching thread IDs.
          executor.ScheduleFor(
              [&] { count.DecrementCount(); }, 123456,
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
        },
        AsyncPriority::Normal,
        AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
  }
  // Waits some time to finish the work.
  count.Wait();
  executor.Stop();
}

TEST(AsyncExecutorTests, CountWorkSingleThreadUrgentToNormal) {
  constexpr int kQueueCap = 10;
  AsyncExecutor executor(1, kQueueCap);
  ASSERT_SUCCESS(executor.Init());
  ASSERT_SUCCESS(executor.Run());
  absl::BlockingCounter count(kQueueCap);
  for (int i = 0; i < kQueueCap / 2; i++) {
    executor.ScheduleFor(
        [&] {
          count.DecrementCount();
          // Schedule another incrementation - test the affinitized path with
          // matching thread IDs.
          executor.Schedule(
              [&] { count.DecrementCount(); }, AsyncPriority::Normal,
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
        },
        123456,
        AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor);
  }
  // Waits some time to finish the work.
  count.Wait();
  executor.Stop();
}

TEST(AsyncExecutorTests, CountWorkMultipleThread) {
  constexpr int kQueueCap = 50;
  AsyncExecutor executor(10, kQueueCap);
  executor.Init();
  executor.Run();

  absl::BlockingCounter count(kQueueCap);
  for (int i = 0; i < kQueueCap; i++) {
    executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::Normal);
  }
  // Waits some time to finish the work.
  count.Wait();
  executor.Stop();
}

TEST(AsyncExecutorTests, AsyncContextCallback) {
  AsyncExecutor executor(1, 10);
  executor.Init();
  executor.Run();

  {
    absl::Notification callback_count;
    auto request = std::make_shared<std::string>("request");
    auto callback = [&](AsyncContext<std::string, std::string>& context) {
      callback_count.Notify();
    };
    auto context = AsyncContext<std::string, std::string>(request, callback);

    executor.Schedule(
        [&] {
          context.response = std::make_shared<std::string>("response");
          context.result = SuccessExecutionResult();
          context.Finish();
        },
        AsyncPriority::Normal);

    // Waits some time to finish the work.
    callback_count.WaitForNotification();

    // Verifies the work is executed.
    ASSERT_SUCCESS(context.result);
    EXPECT_EQ(*(context.response), "response");
  }

  {
    // Atomic is not used here because we just reserve one thread in the
    absl::Notification callback_count;
    auto request = std::make_shared<std::string>("request");
    auto callback = [&](AsyncContext<std::string, std::string>& context) {
      callback_count.Notify();
    };
    auto context = AsyncContext<std::string, std::string>(request, callback);

    executor.ScheduleFor(
        [&] {
          context.response = std::make_shared<std::string>("response");
          context.result = SuccessExecutionResult();
          context.Finish();
        },
        12345);

    // Waits some time to finish the work.
    callback_count.WaitForNotification();

    // Verifies the work is executed.
    ASSERT_SUCCESS(context.result);
    EXPECT_EQ(*(context.response), "response");
  }

  executor.Stop();
}

TEST(AsyncExecutorTests, FinishWorkWhenStopInMiddle) {
  constexpr int kQueueCap = 5;
  AsyncExecutor executor(2, kQueueCap);
  executor.Init();
  executor.Run();

  absl::Mutex count_mu;
  int normal_count = 0;
  for (int i = 0; i < kQueueCap; i++) {
    executor.Schedule(
        [&] {
          {
            absl::MutexLock l(&count_mu);
            normal_count++;
          }
          std::this_thread::sleep_for(UNIT_TEST_SHORT_SLEEP_MS);
        },
        AsyncPriority::Normal);
  }

  int urgent_count = 0;
  for (int i = 0; i < kQueueCap; i++) {
    executor.Schedule(
        [&] {
          {
            absl::MutexLock l(&count_mu);
            urgent_count++;
          }
          std::this_thread::sleep_for(UNIT_TEST_SHORT_SLEEP_MS);
        },
        AsyncPriority::Urgent);
  }
  executor.Stop();

  // Waits some time to finish the work.
  {
    absl::MutexLock l(&count_mu);
    auto condition_fn = [&] {
      count_mu.AssertReaderHeld();
      return urgent_count == kQueueCap && normal_count == kQueueCap;
    };
    count_mu.Await(absl::Condition(&condition_fn));
  }

  EXPECT_EQ(urgent_count, kQueueCap);
  EXPECT_EQ(normal_count, kQueueCap);
}

// TODO(b/315999983): Remove this class.
class AsyncExecutorAccessor : public AsyncExecutor {
 public:
  explicit AsyncExecutorAccessor(size_t thread_count = 1)
      : AsyncExecutor(thread_count, 1 /* queue cap */) {}

  void TestPickTaskExecutorRoundRobinGlobalUrgentPool() {
    int num_executors = 10;
    std::vector<std::unique_ptr<SingleThreadPriorityAsyncExecutor>>
        task_executor_pool;
    for (int i = 0; i < num_executors; i++) {
      task_executor_pool.push_back(
          std::make_unique<SingleThreadPriorityAsyncExecutor>(
              100 /* queue cap */));
    }

    // Run picking executors
    absl::flat_hash_map<SingleThreadPriorityAsyncExecutor*, int>
        task_executor_pool_picked_counts;
    for (int i = 0; i < num_executors; i++) {
      auto task_executor_or =
          PickTaskExecutor(AsyncExecutorAffinitySetting::NonAffinitized,
                           task_executor_pool, TaskExecutorPoolType::UrgentPool,
                           TaskLoadBalancingScheme::RoundRobinGlobal);
      ASSERT_SUCCESS(task_executor_or);
      task_executor_pool_picked_counts[*task_executor_or] += 1;
    }

    // Verify the picked counts are 1 on all the executors
    for (const auto& task_executor : task_executor_pool) {
      EXPECT_EQ(task_executor_pool_picked_counts[task_executor.get()], 1);
    }
  }

  void TestPickTaskExecutorRoundRobinGlobalNonUrgentPool() {
    int num_executors = 10;
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>> task_executor_pool;
    for (int i = 0; i < num_executors; i++) {
      task_executor_pool.push_back(
          std::make_unique<SingleThreadAsyncExecutor>(100 /* queue cap */));
    }

    // Run picking executors
    absl::flat_hash_map<SingleThreadAsyncExecutor*, int>
        task_executor_pool_picked_counts;
    for (int i = 0; i < num_executors; i++) {
      auto task_executor_or = PickTaskExecutor(
          AsyncExecutorAffinitySetting::NonAffinitized, task_executor_pool,
          TaskExecutorPoolType::NotUrgentPool,
          TaskLoadBalancingScheme::RoundRobinGlobal);
      ASSERT_SUCCESS(task_executor_or);
      task_executor_pool_picked_counts[*task_executor_or] += 1;
    }

    // Verify the picked counts are 1 on all the executors
    for (const auto& task_executor : task_executor_pool) {
      EXPECT_EQ(task_executor_pool_picked_counts[task_executor.get()], 1);
    }
  }

  void PickTaskExecutorRoundRobinThreadLocalUrgentPool() {
    int num_executors = 10;
    std::vector<std::unique_ptr<SingleThreadPriorityAsyncExecutor>>
        task_executor_pool;
    for (int i = 0; i < num_executors; i++) {
      task_executor_pool.push_back(
          std::make_unique<SingleThreadPriorityAsyncExecutor>(
              100 /* queue cap */));
    }

    // Run picking executors
    absl::flat_hash_map<SingleThreadPriorityAsyncExecutor*, int>
        task_executor_pool_picked_counts;
    for (int i = 0; i < num_executors; i++) {
      auto task_executor_or =
          PickTaskExecutor(AsyncExecutorAffinitySetting::NonAffinitized,
                           task_executor_pool, TaskExecutorPoolType::UrgentPool,
                           TaskLoadBalancingScheme::RoundRobinPerThread);
      ASSERT_SUCCESS(task_executor_or);
      task_executor_pool_picked_counts[*task_executor_or] += 1;
    }

    // Verify the picked counts are 1 on all the executors
    for (const auto& task_executor : task_executor_pool) {
      EXPECT_EQ(task_executor_pool_picked_counts[task_executor.get()], 1);
    }

    // A different thread picks round robin as well.
    std::thread thread([&] {
      for (int i = 0; i < num_executors; i++) {
        auto task_executor_or = PickTaskExecutor(
            AsyncExecutorAffinitySetting::NonAffinitized, task_executor_pool,
            TaskExecutorPoolType::UrgentPool,
            TaskLoadBalancingScheme::RoundRobinPerThread);
        ASSERT_SUCCESS(task_executor_or);
        task_executor_pool_picked_counts[*task_executor_or] += 1;
      }

      // Verify the picked counts are 2 on all the executors
      for (const auto& task_executor : task_executor_pool) {
        EXPECT_EQ(task_executor_pool_picked_counts[task_executor.get()], 2);
      }
    });
    thread.join();
  }

  void PickTaskExecutorRoundRobinThreadLocalNonUrgentPool() {
    int num_executors = 10;
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>> task_executor_pool;
    for (int i = 0; i < num_executors; i++) {
      task_executor_pool.push_back(
          std::make_unique<SingleThreadAsyncExecutor>(100 /* queue cap */));
    }

    // Run picking executors
    absl::flat_hash_map<SingleThreadAsyncExecutor*, int>
        task_executor_pool_picked_counts;
    for (int i = 0; i < num_executors; i++) {
      auto task_executor_or = PickTaskExecutor(
          AsyncExecutorAffinitySetting::NonAffinitized, task_executor_pool,
          TaskExecutorPoolType::NotUrgentPool,
          TaskLoadBalancingScheme::RoundRobinPerThread);
      ASSERT_SUCCESS(task_executor_or);
      task_executor_pool_picked_counts[*task_executor_or] += 1;
    }

    // Verify the picked counts are 1 on all the executors
    for (const auto& task_executor : task_executor_pool) {
      EXPECT_EQ(task_executor_pool_picked_counts[task_executor.get()], 1);
    }
  }

  void PickTaskExecutorRoundRobinThreadLocalConcurrent() {
    int num_executors = 40;
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>> task_executor_pool;
    for (int i = 0; i < num_executors; i++) {
      task_executor_pool.push_back(
          std::make_unique<SingleThreadAsyncExecutor>(100 /* queue cap */));
    }

    // Run picking executors
    absl::Mutex task_executor_pool_picked_counts_mu;
    absl::flat_hash_map<SingleThreadAsyncExecutor*, int>
        task_executor_pool_picked_counts;

    auto picking_function = [&](int pick_times) {
      for (int i = 0; i < pick_times; i++) {
        auto task_executor_or = PickTaskExecutor(
            AsyncExecutorAffinitySetting::NonAffinitized, task_executor_pool,
            TaskExecutorPoolType::NotUrgentPool,
            TaskLoadBalancingScheme::RoundRobinPerThread);
        ASSERT_SUCCESS(task_executor_or);
        absl::MutexLock l(&task_executor_pool_picked_counts_mu);
        task_executor_pool_picked_counts[*task_executor_or] += 1;
      }
    };

    // 40 tasks for the 40 executors.
    std::thread thread1(picking_function, 15);
    std::thread thread2(picking_function, 4);
    std::thread thread3(picking_function, 10);
    std::thread thread4(picking_function, 11);

    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();

    // Verify the picked counts are atleast 2 on one of the executors
    // since tasks are picked w.r.t. thread local weak counters
    bool atleast_one_executor_picked_twice = false;
    size_t total_count = 0;
    for (const auto& task_executor : task_executor_pool) {
      if (task_executor_pool_picked_counts[task_executor.get()] >= 2) {
        atleast_one_executor_picked_twice = true;
      }
      total_count += task_executor_pool_picked_counts[task_executor.get()];
    }
    ASSERT_EQ(atleast_one_executor_picked_twice, true);
    ASSERT_EQ(total_count, 40);
  }

  void PickTaskExecutorRoundRobinGlobalConcurrent() {
    int num_executors = 40;
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>> task_executor_pool;
    for (int i = 0; i < num_executors; i++) {
      task_executor_pool.push_back(
          std::make_unique<SingleThreadAsyncExecutor>(100 /* queue cap */));
    }

    // Run picking executors
    absl::Mutex task_executor_pool_picked_counts_mu;
    absl::flat_hash_map<SingleThreadAsyncExecutor*, int>
        task_executor_pool_picked_counts;

    auto picking_function = [&](int pick_times) {
      for (int i = 0; i < pick_times; i++) {
        auto task_executor_or = PickTaskExecutor(
            AsyncExecutorAffinitySetting::NonAffinitized, task_executor_pool,
            TaskExecutorPoolType::NotUrgentPool,
            TaskLoadBalancingScheme::RoundRobinGlobal);
        ASSERT_SUCCESS(task_executor_or);
        absl::MutexLock l(&task_executor_pool_picked_counts_mu);
        task_executor_pool_picked_counts[*task_executor_or] += 1;
      }
    };

    // 40 tasks for the 40 executors.
    std::thread thread1(picking_function, 15);
    std::thread thread2(picking_function, 4);
    std::thread thread3(picking_function, 10);
    std::thread thread4(picking_function, 11);

    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();

    // Verify the picked counts are 1 on all the executors
    // since threads pick w.r.t. global strong task count
    size_t total_count = 0;
    for (const auto& task_executor : task_executor_pool) {
      EXPECT_EQ(task_executor_pool_picked_counts[task_executor.get()], 1);
      total_count += task_executor_pool_picked_counts[task_executor.get()];
    }
    ASSERT_EQ(total_count, 40);
  }

  void TestPickRandomTaskExecutorWithAffinity() {
    ASSERT_SUCCESS(Init());
    ASSERT_SUCCESS(Run());
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>> task_executor_pool;
    task_executor_pool.push_back(
        std::make_unique<SingleThreadAsyncExecutor>(100 /* queue cap */));
    auto& executor = task_executor_pool.back();
    ASSERT_SUCCESS(executor->Init());
    ASSERT_SUCCESS(executor->Run());
    const auto expected_id = *executor->GetThreadId();
    auto chosen_task_executor_or = PickTaskExecutor(
        AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor,
        task_executor_pool, TaskExecutorPoolType::NotUrgentPool,
        TaskLoadBalancingScheme::Random);

    ASSERT_SUCCESS(chosen_task_executor_or);

    // Picking an executor should result in a random executor being chosen.
    EXPECT_THAT((*chosen_task_executor_or)->GetThreadId(),
                IsSuccessfulAndHolds(expected_id));
    EXPECT_SUCCESS(executor->Stop());
    EXPECT_SUCCESS(Stop());
  }

  void TestPickNonUrgentToNonUrgentTaskExecutorWithAffinity() {
    ASSERT_SUCCESS(Init());
    ASSERT_SUCCESS(Run());
    // Scheduling another task with affinity should result in using the same
    // thread.
    absl::Notification done;
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>>
        task_executor_pool;  // unused.
    // Schedule arbitrary work to be done. Using the chosen thread of this work,
    // ensure that picking another executor with affinity chooses this same
    // thread.
    Schedule(
        [this, &done, &task_executor_pool] {
          auto chosen_task_executor_or = PickTaskExecutor(
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor,
              task_executor_pool, TaskExecutorPoolType::NotUrgentPool,
              TaskLoadBalancingScheme::Random);
          ASSERT_SUCCESS(chosen_task_executor_or);
          // Picking an executor should choose the executor owning the current
          // thread.
          EXPECT_THAT((*chosen_task_executor_or)->GetThreadId(),
                      IsSuccessfulAndHolds(std::this_thread::get_id()));
          done.Notify();
        },
        AsyncPriority::Normal);
    done.WaitForNotification();
    EXPECT_SUCCESS(Stop());
  }

  void TestPickNonUrgentToUrgentTaskExecutorWithAffinity() {
    ASSERT_SUCCESS(Init());
    ASSERT_SUCCESS(Run());
    // Scheduling another task with affinity should result in using the same
    // thread.
    absl::Notification done;
    std::vector<std::unique_ptr<SingleThreadPriorityAsyncExecutor>>
        task_executor_pool;  // unused.
    // Schedule arbitrary work to be done. Using the chosen thread of this work,
    // ensure that picking another executor with affinity chooses this same
    // thread.
    Schedule(
        [this, &done, &task_executor_pool] {
          auto chosen_task_executor_or = PickTaskExecutor(
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor,
              task_executor_pool, TaskExecutorPoolType::UrgentPool,
              TaskLoadBalancingScheme::Random);
          ASSERT_SUCCESS(chosen_task_executor_or);
          // Lookup the corresponding threads in the map.
          const auto& [normal_executor, urgent_executor] =
              this->thread_id_to_executor_map_[std::this_thread::get_id()];
          EXPECT_EQ(urgent_executor, *chosen_task_executor_or);
          done.Notify();
        },
        AsyncPriority::Normal);
    done.WaitForNotification();
    EXPECT_SUCCESS(Stop());
  }

  void TestPickUrgentToUrgentTaskExecutorWithAffinity() {
    ASSERT_SUCCESS(Init());
    ASSERT_SUCCESS(Run());
    // Scheduling another task with affinity should result in using the same
    // thread.
    absl::Notification done;
    std::vector<std::unique_ptr<SingleThreadPriorityAsyncExecutor>>
        task_executor_pool;  // unused.
    // Schedule arbitrary work to be done. Using the chosen thread of this work,
    // ensure that picking another executor with affinity chooses this same
    // thread.
    ScheduleFor(
        [this, &done, &task_executor_pool] {
          auto chosen_task_executor_or = PickTaskExecutor(
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor,
              task_executor_pool, TaskExecutorPoolType::NotUrgentPool,
              TaskLoadBalancingScheme::Random);
          ASSERT_SUCCESS(chosen_task_executor_or);
          // Picking an executor should choose the executor owning the current
          // thread.
          EXPECT_THAT((*chosen_task_executor_or)->GetThreadId(),
                      IsSuccessfulAndHolds(std::this_thread::get_id()));
          done.Notify();
        },
        123456);
    done.WaitForNotification();
    EXPECT_SUCCESS(Stop());
  }

  void TestPickUrgentToNonUrgentTaskExecutorWithAffinity() {
    ASSERT_SUCCESS(Init());
    ASSERT_SUCCESS(Run());
    // Scheduling another task with affinity should result in using the same
    // thread.
    absl::Notification done;
    std::vector<std::unique_ptr<SingleThreadAsyncExecutor>>
        task_executor_pool;  // unused.
    // Schedule arbitrary work to be done. Using the chosen thread of this work,
    // ensure that picking another executor with affinity chooses this same
    // thread.
    ScheduleFor(
        [this, &done, &task_executor_pool] {
          auto chosen_task_executor_or = PickTaskExecutor(
              AsyncExecutorAffinitySetting::AffinitizedToCallingAsyncExecutor,
              task_executor_pool, TaskExecutorPoolType::NotUrgentPool,
              TaskLoadBalancingScheme::Random);
          ASSERT_SUCCESS(chosen_task_executor_or);
          // Lookup the corresponding threads in the map.
          const auto& [normal_executor, urgent_executor] =
              this->thread_id_to_executor_map_[std::this_thread::get_id()];
          EXPECT_EQ(normal_executor, *chosen_task_executor_or);
          done.Notify();
        },
        123456);
    done.WaitForNotification();
    EXPECT_SUCCESS(Stop());
  }
};

TEST(AsyncExecutorTests, PickTaskExecutorRoundRobinGlobalUrgentPool) {
  AsyncExecutorAccessor().TestPickTaskExecutorRoundRobinGlobalUrgentPool();
}

TEST(AsyncExecutorTests, PickTaskExecutorRoundRobinGlobalNonUrgentPool) {
  AsyncExecutorAccessor().TestPickTaskExecutorRoundRobinGlobalNonUrgentPool();
}

TEST(AsyncExecutorTests, PickTaskExecutorRoundRobinThreadLocalUrgentPool) {
  AsyncExecutorAccessor().PickTaskExecutorRoundRobinThreadLocalUrgentPool();
}

TEST(AsyncExecutorTests, PickTaskExecutorRoundRobinThreadLocalNonUrgentPool) {
  AsyncExecutorAccessor().PickTaskExecutorRoundRobinThreadLocalNonUrgentPool();
}

TEST(AsyncExecutorTests, PickTaskExecutorRoundRobinThreadLocalConcurrent) {
  // Does not differentiate between urgent and non urgent modes.
  AsyncExecutorAccessor().PickTaskExecutorRoundRobinThreadLocalConcurrent();
}

TEST(AsyncExecutorTests, PickTaskExecutorRoundRobinGlobalConcurrent) {
  // Does not differentiate between urgent and non urgent modes.
  AsyncExecutorAccessor().PickTaskExecutorRoundRobinGlobalConcurrent();
}

TEST(AsyncExecutorTests, TestPickRandomTaskExecutorWithAffinity) {
  // Picks random executor even with affinity.
  AsyncExecutorAccessor().TestPickRandomTaskExecutorWithAffinity();
}

TEST(AsyncExecutorTests, TestPickNonUrgentToNonUrgentTaskExecutorWithAffinity) {
  // Picks the same non-urgent thread when executing subsequent work.
  AsyncExecutorAccessor(10)
      .TestPickNonUrgentToNonUrgentTaskExecutorWithAffinity();
}

TEST(AsyncExecutorTests, TestPickNonUrgentToUrgentTaskExecutorWithAffinity) {
  // Picks the urgent thread with the same affinity when executing subsequent
  // work.
  AsyncExecutorAccessor(10).TestPickNonUrgentToUrgentTaskExecutorWithAffinity();
}

TEST(AsyncExecutorTests, TestPickUrgentToUrgentTaskExecutorWithAffinity) {
  // Picks the non-urgent thread with the same affinity when executing
  // subsequent work.
  AsyncExecutorAccessor(10).TestPickUrgentToUrgentTaskExecutorWithAffinity();
}

TEST(AsyncExecutorTests, TestPickUrgentToNonUrgentTaskExecutorWithAffinity) {
  // Picks the non-urgent thread with the same affinity when executing
  // subsequent work.
  AsyncExecutorAccessor(10).TestPickUrgentToNonUrgentTaskExecutorWithAffinity();
}
}  // namespace google::scp::core::test
