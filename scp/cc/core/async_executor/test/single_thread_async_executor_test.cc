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

#include "core/async_executor/src/single_thread_async_executor.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>

#include "absl/synchronization/blocking_counter.h"
#include "absl/synchronization/mutex.h"
#include "core/async_executor/mock/mock_async_executor_with_internals.h"
#include "core/async_executor/src/error_codes.h"
#include "core/async_executor/src/typedef.h"
#include "core/common/time_provider/src/time_provider.h"
#include "core/interface/async_context.h"
#include "core/interface/async_executor_interface.h"
#include "core/test/test_config.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"

using google::scp::core::common::TimeProvider;
using testing::Values;

namespace google::scp::core::test {
TEST(SingleThreadAsyncExecutorTests, CannotInitWithTooBigQueueCap) {
  SingleThreadAsyncExecutor executor(kMaxQueueCap + 1);
  EXPECT_THAT(executor.Init(),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_INVALID_QUEUE_CAP)));
}

TEST(SingleThreadAsyncExecutorTests, EmptyWorkQueue) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_SUCCESS(executor.Init());
  EXPECT_SUCCESS(executor.Run());
  EXPECT_SUCCESS(executor.Stop());
}

TEST(SingleThreadAsyncExecutorTests, CannotRunTwice) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_SUCCESS(executor.Init());
  EXPECT_SUCCESS(executor.Run());
  EXPECT_THAT(executor.Run(), ResultIs(FailureExecutionResult(
                                  errors::SC_ASYNC_EXECUTOR_ALREADY_RUNNING)));
  EXPECT_SUCCESS(executor.Stop());
}

TEST(SingleThreadAsyncExecutorTests, CannotStopTwice) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_SUCCESS(executor.Init());
  EXPECT_SUCCESS(executor.Run());
  EXPECT_SUCCESS(executor.Stop());
  EXPECT_THAT(
      executor.Stop(),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(SingleThreadAsyncExecutorTests, CannotScheduleWorkBeforeInit) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_THAT(
      executor.Schedule([] {}, AsyncPriority::Normal),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(SingleThreadAsyncExecutorTests, CannotScheduleWorkBeforeRun) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_SUCCESS(executor.Init());
  EXPECT_THAT(
      executor.Schedule([] {}, AsyncPriority::Normal),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(SingleThreadAsyncExecutorTests, CannotRunBeforeInit) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_THAT(executor.Run(), ResultIs(FailureExecutionResult(
                                  errors::SC_ASYNC_EXECUTOR_NOT_INITIALIZED)));
}

TEST(SingleThreadAsyncExecutorTests, CannotStopBeforeRun) {
  SingleThreadAsyncExecutor executor(10);
  EXPECT_SUCCESS(executor.Init());
  EXPECT_THAT(
      executor.Stop(),
      ResultIs(FailureExecutionResult(errors::SC_ASYNC_EXECUTOR_NOT_RUNNING)));
}

TEST(SingleThreadAsyncExecutorTests, ExceedingQueueCapSchedule) {
  constexpr int kQueueCap = 1;
  SingleThreadAsyncExecutor executor(kQueueCap);
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

  executor.Stop();
}

TEST(SingleThreadAsyncExecutorTests, CountWorkSingleThread) {
  constexpr int kQueueCap = 10;
  SingleThreadAsyncExecutor executor(kQueueCap);
  executor.Init();
  executor.Run();
  {
    absl::BlockingCounter count(kQueueCap);
    for (int i = 0; i < kQueueCap / 2; i++) {
      executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::Normal);
      executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::High);
    }
    // Waits some time to finish the work.
    count.Wait();
  }
  executor.Stop();
}

class AffinityTest : public testing::TestWithParam<size_t> {
 protected:
  size_t GetCpu() const { return GetParam(); }
};

TEST_P(AffinityTest, CountWorkSingleThreadWithAffinity) {
  constexpr int kQueueCap = 10;
  SingleThreadAsyncExecutor executor(kQueueCap, GetCpu());
  executor.Init();
  executor.Run();
  {
    absl::BlockingCounter count(kQueueCap);
    for (int i = 0; i < kQueueCap / 2; i++) {
      executor.Schedule(
          [&] {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
            if (GetCpu() < std::thread::hardware_concurrency()) {
              EXPECT_NE(CPU_ISSET(GetCpu(), &cpuset), 0);
            }
            count.DecrementCount();
          },
          AsyncPriority::Normal);
      executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::High);
    }
    // Waits some time to finish the work.
    count.Wait();
  }
  executor.Stop();
}

// The test should work for any value, even an invalid CPU #.
INSTANTIATE_TEST_SUITE_P(SingleThreadAsyncExecutorTests, AffinityTest,
                         Values(0, 1, std::thread::hardware_concurrency() - 1,
                                std::thread::hardware_concurrency()));

TEST(SingleThreadAsyncExecutorTests, CannotScheduleHiPri) {
  constexpr int kQueueCap = 50;
  SingleThreadAsyncExecutor executor(kQueueCap);
  executor.Init();
  executor.Run();

  EXPECT_THAT(executor.Schedule([&] {}, AsyncPriority::Urgent),
              ResultIs(FailureExecutionResult(
                  errors::SC_ASYNC_EXECUTOR_INVALID_PRIORITY_TYPE)));
  executor.Stop();
}

TEST(SingleThreadAsyncExecutorTests, CountWorkMultipleThread) {
  constexpr int kQueueCap = 50;
  SingleThreadAsyncExecutor executor(kQueueCap);
  executor.Init();
  executor.Run();

  absl::BlockingCounter count(kQueueCap);
  for (int i = 0; i < kQueueCap / 2; i++) {
    executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::Normal);
    executor.Schedule([&] { count.DecrementCount(); }, AsyncPriority::High);
  }
  // Waits some time to finish the work.
  count.Wait();
  executor.Stop();
}

TEST(SingleThreadAsyncExecutorTests, AsyncContextCallback) {
  SingleThreadAsyncExecutor executor(10);
  executor.Init();
  executor.Run();

  {
    absl::Mutex callback_count_mu;
    size_t callback_count = 0;
    auto request = std::make_shared<std::string>("request");
    auto callback = [&](AsyncContext<std::string, std::string>& context) {
      absl::MutexLock l(&callback_count_mu);
      callback_count++;
    };
    auto context = AsyncContext<std::string, std::string>(request, callback);

    executor.Schedule(
        [&] {
          context.response = std::make_shared<std::string>("response");
          context.result = SuccessExecutionResult();
          context.Finish();
        },
        AsyncPriority::Normal);
    {
      absl::MutexLock l(&callback_count_mu);
      auto condition_fn = [&] {
        callback_count_mu.AssertReaderHeld();
        return callback_count == 1;
      };
      callback_count_mu.Await(absl::Condition(&condition_fn));
    }

    executor.Schedule(
        [&] {
          context.response = std::make_shared<std::string>("response");
          context.result = SuccessExecutionResult();
          context.Finish();
        },
        AsyncPriority::High);
    {
      absl::MutexLock l(&callback_count_mu);
      auto condition_fn = [&] {
        callback_count_mu.AssertReaderHeld();
        return callback_count == 2;
      };
      callback_count_mu.Await(absl::Condition(&condition_fn));
    }

    // Verifies the work is executed.
    EXPECT_EQ(*(context.response), "response");
    EXPECT_SUCCESS(context.result);
  }

  executor.Stop();
}

TEST(SingleThreadAsyncExecutorTests, FinishWorkWhenStopInMiddle) {
  constexpr int kQueueCap = 6;
  SingleThreadAsyncExecutor executor(kQueueCap);
  executor.Init();
  executor.Run();

  absl::Mutex count_mu;
  int normal_count = 0;
  int medium_count = 0;
  for (int i = 0; i < kQueueCap / 2; i++) {
    executor.Schedule(
        [&] {
          {
            absl::MutexLock l(&count_mu);
            normal_count++;
          }
          std::this_thread::sleep_for(UNIT_TEST_SHORT_SLEEP_MS);
        },
        AsyncPriority::Normal);

    executor.Schedule(
        [&] {
          {
            absl::MutexLock l(&count_mu);
            medium_count++;
          }
          std::this_thread::sleep_for(UNIT_TEST_SHORT_SLEEP_MS);
        },
        AsyncPriority::High);
  }

  executor.Stop();
  {
    absl::MutexLock l(&count_mu);
    auto condition_fn = [&] {
      count_mu.AssertReaderHeld();
      return medium_count + normal_count == kQueueCap;
    };
    count_mu.Await(absl::Condition(&condition_fn));
  }
}
}  // namespace google::scp::core::test
