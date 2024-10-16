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

#include "roma/sandbox/dispatcher/src/dispatcher.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "core/async_executor/src/async_executor.h"
#include "core/test/utils/auto_init_run_stop.h"
#include "public/core/test/interface/execution_result_matchers.h"
#include "roma/interface/roma.h"
#include "roma/sandbox/dispatcher/src/error_codes.h"
#include "roma/sandbox/worker_api/src/worker_api.h"
#include "roma/sandbox/worker_api/src/worker_api_sapi.h"
#include "roma/sandbox/worker_pool/src/worker_pool.h"
#include "roma/sandbox/worker_pool/src/worker_pool_api_sapi.h"

using google::scp::core::AsyncExecutor;
using google::scp::core::ExecutionResultOr;
using google::scp::core::FailureExecutionResult;
using google::scp::core::errors::
    SC_ROMA_DISPATCHER_DISPATCH_DISALLOWED_MULTIPLE_BYTE_STR_INPUTS;
using google::scp::core::test::AutoInitRunStop;
using google::scp::roma::sandbox::worker_api::WorkerApi;
using google::scp::roma::sandbox::worker_api::WorkerApiSapi;
using google::scp::roma::sandbox::worker_api::WorkerApiSapiConfig;
using google::scp::roma::sandbox::worker_pool::WorkerPool;
using google::scp::roma::sandbox::worker_pool::WorkerPoolApiSapi;
using ::testing::StrEq;

namespace {
WorkerApiSapiConfig CreateWorkerApiSapiConfig() {
  WorkerApiSapiConfig config;
  config.js_engine_require_code_preload = true;
  config.compilation_context_cache_size = 5;
  config.native_js_function_comms_fd = -1;
  config.native_js_function_names = std::vector<std::string>();
  config.max_worker_virtual_memory_mb = 0;
  config.sandbox_request_response_shared_buffer_size_mb = 0;
  config.enable_sandbox_sharing_request_response_with_buffer_only = false;
  return config;
}
}  // namespace

namespace google::scp::roma::sandbox::dispatcher::test {

TEST(DispatcherTest, CanRunCode) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  auto load_request = std::make_unique<CodeObject>();
  load_request->id = "some_id";
  load_request->version_string = "v1";
  load_request->js =
      "function test(input) { return input + \" Some string\"; }";

  absl::Notification done_loading;

  auto result = dispatcher.Dispatch(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        done_loading.Notify();
      });
  ASSERT_SUCCESS(result);

  done_loading.WaitForNotification();

  auto execute_request = std::make_unique<InvocationStrRequest<>>();
  execute_request->id = "some_id";
  execute_request->version_string = "v1";
  execute_request->handler_name = "test";
  execute_request->input.push_back(R"("Hello")");

  absl::Notification done_executing;

  result = dispatcher.Dispatch(
      std::move(execute_request),
      [&done_executing](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        EXPECT_THAT((*resp)->resp, StrEq(R"("Hello Some string")"));
        done_executing.Notify();
      });

  ASSERT_SUCCESS(result);

  done_executing.WaitForNotification();
}

TEST(DispatcherTest, CanRunStringViewInputCode) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  auto load_request = std::make_unique<CodeObject>();
  load_request->id = "some_id";
  load_request->version_string = "v1";
  load_request->js =
      "function test(input) { return input + \" Some string\"; }";

  absl::Notification done_loading;

  auto result = dispatcher.Dispatch(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        done_loading.Notify();
      });
  ASSERT_SUCCESS(result);

  done_loading.WaitForNotification();

  std::string_view input_str_view{R"("Hello")"};
  auto execute_request =
      std::make_unique<InvocationStrViewRequest<>>(InvocationStrViewRequest<>{
          .id = "some_id",
          .version_string = "v1",
          .handler_name = "test",
          .input = {input_str_view},
      });

  absl::Notification done_executing;

  result = dispatcher.Dispatch(
      std::move(execute_request),
      [&done_executing](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        EXPECT_THAT((*resp)->resp, StrEq(R"("Hello Some string")"));
        done_executing.Notify();
      });

  ASSERT_SUCCESS(result);

  done_executing.WaitForNotification();
}

TEST(DispatcherTest, CanHandleCodeFailures) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  auto load_request = std::make_unique<CodeObject>();
  load_request->id = "some_id";
  load_request->version_string = "v1";
  // Bad JS
  load_request->js = "function test(input) { ";

  absl::Notification done_loading;
  auto result = dispatcher.Dispatch(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        // That didn't work
        EXPECT_FALSE(resp->ok());
        done_loading.Notify();
      });

  ASSERT_SUCCESS(result);
  done_loading.WaitForNotification();
}

TEST(DispatcherTest, CanHandleExecuteWithoutLoadFailure) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  auto execute_request = std::make_unique<InvocationStrRequest<>>();
  execute_request->id = "some_id";
  execute_request->version_string = "v1";
  execute_request->handler_name = "test";
  execute_request->input.push_back(R"("Hello")");

  absl::Notification done_executing;
  auto result = dispatcher.Dispatch(
      std::move(execute_request),
      [&done_executing](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_FALSE(resp->ok());
        done_executing.Notify();
      });

  ASSERT_SUCCESS(result);
  done_executing.WaitForNotification();
}

TEST(DispatcherTest, BroadcastShouldUpdateAllWorkers) {
  constexpr size_t kNumberOfWorkers = 5;
  AsyncExecutor async_executor(kNumberOfWorkers, 100);

  std::vector<WorkerApiSapiConfig> configs;
  for (int i = 0; i < kNumberOfWorkers; i++) {
    configs.push_back(CreateWorkerApiSapiConfig());
  }

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 100, 5);

  auto load_request = std::make_unique<CodeObject>();
  load_request->id = "some_id";
  load_request->version_string = "v1";
  load_request->js = R"(test = (s) => s + " Some string";)";

  absl::Notification done_loading;
  auto result = dispatcher.Broadcast(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        done_loading.Notify();
      });

  ASSERT_SUCCESS(result);
  done_loading.WaitForNotification();

  absl::Mutex execution_count_mu;
  int execution_count = 0;
  // More than the number of workers to make sure the requests can indeed run in
  // all workers.
  constexpr int kRequestSent = kNumberOfWorkers * 3;

  for (int i = 0; i < kRequestSent; i++) {
    auto execute_request = std::make_unique<InvocationStrRequest<>>();
    execute_request->id = absl::StrCat("some_id", i);
    execute_request->version_string = "v1";
    execute_request->handler_name = "test";
    execute_request->input.push_back(absl::StrCat(R"("Hello)", i, "\""));

    result = dispatcher.Dispatch(
        std::move(execute_request),
        [&, i](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          EXPECT_THAT((*resp)->resp,
                      absl::StrCat(R"("Hello)", i, R"( Some string")"));
          absl::MutexLock l(&execution_count_mu);
          execution_count++;
        });

    ASSERT_SUCCESS(result);
  }

  {
    absl::MutexLock l(&execution_count_mu);
    auto condition_fn = [&] {
      execution_count_mu.AssertReaderHeld();
      return execution_count >= kRequestSent;
    };
    execution_count_mu.Await(absl::Condition(&condition_fn));
  }
}

TEST(DispatcherTest, BroadcastShouldExitGracefullyIfThereAreErrorsWithTheCode) {
  constexpr size_t kNumberOfWorkers = 5;
  AsyncExecutor async_executor(kNumberOfWorkers, 100);

  std::vector<WorkerApiSapiConfig> configs;
  for (int i = 0; i < kNumberOfWorkers; i++) {
    configs.push_back(CreateWorkerApiSapiConfig());
  }

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 100, 5);

  auto load_request = std::make_unique<CodeObject>();
  load_request->id = "some_id";
  load_request->version_string = "v1";
  // Bad syntax
  load_request->js = "function test(s) { return";

  absl::Notification done_loading;
  auto result = dispatcher.Broadcast(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        // That failed
        EXPECT_FALSE(resp->ok());
        done_loading.Notify();
      });

  ASSERT_SUCCESS(result);
  done_loading.WaitForNotification();
}

TEST(DispatcherTest, DispatchBatchShouldExecuteAllRequests) {
  constexpr size_t kNumberOfWorkers = 5;
  AsyncExecutor async_executor(kNumberOfWorkers, 100);

  std::vector<WorkerApiSapiConfig> configs;
  for (int i = 0; i < kNumberOfWorkers; i++) {
    configs.push_back(CreateWorkerApiSapiConfig());
  }

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 100, 5);

  {
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id";
    load_request->version_string = "v1";
    load_request->js = R"(test = (s) => s + " Some string";)";

    absl::Notification done_loading;
    auto result = dispatcher.Broadcast(
        std::move(load_request),
        [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          done_loading.Notify();
        });

    ASSERT_SUCCESS(result);
    done_loading.WaitForNotification();
  }

  // More than the number of workers to make sure the requests can indeed run in
  // all workers.
  constexpr int kRequestSent = kNumberOfWorkers * 3;

  std::vector<InvocationStrRequest<>> batch;
  absl::flat_hash_set<std::string> request_ids;

  for (int i = 0; i < kRequestSent; i++) {
    auto execute_request = InvocationStrRequest<>();
    execute_request.id = absl::StrCat("some_id", i);
    execute_request.version_string = "v1";
    execute_request.handler_name = "test";
    execute_request.input.push_back(absl::StrCat(R"("Hello)", i, "\""));

    // Keep track of the request ids
    request_ids.insert(execute_request.id);
    batch.push_back(execute_request);
  }

  absl::Notification finished_batch;
  std::vector<absl::StatusOr<ResponseObject>> test_batch_response;

  dispatcher.DispatchBatch(
      batch,
      [&finished_batch, &test_batch_response](
          const std::vector<absl::StatusOr<ResponseObject>>& batch_response) {
        for (auto& r : batch_response) {
          test_batch_response.push_back(r);
        }
        finished_batch.Notify();
      });

  finished_batch.WaitForNotification();

  for (auto& r : test_batch_response) {
    EXPECT_TRUE(r.ok());
    // Remove the ids we see form the set
    request_ids.erase(r->id);
  }

  // Since we should have a gotten a response for all request ID, we expect all
  // the ids to have been removed from this set.
  EXPECT_TRUE(request_ids.empty());
}

TEST(DispatcherTest, DispatchBatchShouldFailIfQueuesAreFull) {
  // One worker with a one-item queue so that the queue takes long to empty out
  constexpr size_t kNumberOfWorkers = 1;
  AsyncExecutor async_executor(kNumberOfWorkers /*thread_count*/,
                               1 /*queue_cap*/);

  std::vector<WorkerApiSapiConfig> configs = {CreateWorkerApiSapiConfig()};
  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool,
                        100 /*max_pending_requests*/, 5 /*code_version_size*/);

  auto load_request = std::make_unique<CodeObject>();
  load_request->id = "some_id";
  load_request->version_string = "v1";
  // Function that takes long so that queues will have items in it
  load_request->js = R"""(
    function sleep(milliseconds) {
      const date = Date.now();
      let currentDate = null;
      do {
        currentDate = Date.now();
      } while (currentDate - date < milliseconds);
    }

    function takes_long() {
      sleep(2000);
      return "hello";
    }
  )""";

  absl::Notification done_loading;

  auto result = dispatcher.Broadcast(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        done_loading.Notify();
      });
  ASSERT_SUCCESS(result);

  done_loading.WaitForNotification();

  std::vector<InvocationStrRequest<>> batch;
  for (int i = 0; i < 2; i++) {
    auto execute_request = InvocationStrRequest<>();
    execute_request.id = absl::StrCat("some_id", i);
    execute_request.version_string = "v1";
    execute_request.handler_name = "takes_long";
    batch.push_back(execute_request);
  }

  absl::Notification finished_batch;

  result = dispatcher.DispatchBatch(
      batch,
      [&finished_batch](
          const std::vector<absl::StatusOr<ResponseObject>>& batch_response) {
        for (auto& r : batch_response) {
          EXPECT_TRUE(r.ok());
        }
        finished_batch.Notify();
      });

  // This dispatch batch should work as queues were empty
  ASSERT_SUCCESS(result);

  result = dispatcher.DispatchBatch(
      batch,
      [](const std::vector<absl::StatusOr<ResponseObject>>& batch_response) {
        return;
      });

  // This dispatch batch should not work as queues are not empty
  EXPECT_FALSE(result.Successful());

  finished_batch.WaitForNotification();
}

TEST(DispatcherTest, ShouldBeAbleToExecutePreviouslyLoadedCodeAfterCrash) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  // Only one worker in the pool
  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  {
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id";
    load_request->version_string = "v1";
    load_request->js = R"(test = (s) => s + " Some string";)";

    absl::Notification done_loading;
    auto result = dispatcher.Dispatch(
        std::move(load_request),
        [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          done_loading.Notify();
        });

    ASSERT_SUCCESS(result);
    done_loading.WaitForNotification();
  }

  {
    auto execute_request = std::make_unique<InvocationStrRequest<>>();
    execute_request->id = "some_id";
    execute_request->version_string = "v1";
    execute_request->handler_name = "test";
    execute_request->input.push_back(R"("Hello")");

    absl::Notification done_executing;
    auto result = dispatcher.Dispatch(
        std::move(execute_request),
        [&done_executing](
            std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          EXPECT_THAT((*resp)->resp, StrEq(R"("Hello Some string")"));
          done_executing.Notify();
        });

    ASSERT_SUCCESS(result);
    done_executing.WaitForNotification();
  }

  // We loaded and executed successfully, so now we kill the one worker
  auto worker = worker_pool.GetWorker(0);
  ASSERT_SUCCESS(worker.result());
  (*worker)->Terminate();

  // This coming execution we expect will fail since the worker has died. But
  // the execution flow should cause it to be restarted.

  {
    auto execute_request = std::make_unique<InvocationStrRequest<>>();
    execute_request->id = "some_id";
    execute_request->version_string = "v1";
    execute_request->handler_name = "test";
    execute_request->input.push_back(R"("Hello")");

    absl::Notification done_executing;
    auto result = dispatcher.Dispatch(
        std::move(execute_request),
        [&done_executing](
            std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          // This execution should fail since the worker has died
          EXPECT_FALSE(resp->ok());
          done_executing.Notify();
        });

    ASSERT_SUCCESS(result);
    done_executing.WaitForNotification();
  }

  // Now we execute again an this time around we expect it to work
  {
    auto execute_request = std::make_unique<InvocationStrRequest<>>();
    execute_request->id = "some_id";
    execute_request->version_string = "v1";
    execute_request->handler_name = "test";
    execute_request->input.push_back(R"JS("Hello after restart :)")JS");

    absl::Notification done_executing;
    auto result = dispatcher.Dispatch(
        std::move(execute_request),
        [&done_executing](
            std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          EXPECT_THAT((*resp)->resp,
                      StrEq(R"("Hello after restart :) Some string")"));
          done_executing.Notify();
        });

    ASSERT_SUCCESS(result);
    done_executing.WaitForNotification();
  }
}

TEST(DispatcherTest, ShouldRecoverFromWorkerCrashWithMultipleCodeVersions) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  // Only one worker in the pool
  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  {
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id";
    load_request->version_string = "v1";
    load_request->js = R"(test = (s) => s + " Some string 1";)";

    absl::Notification done_loading;
    auto result = dispatcher.Dispatch(
        std::move(load_request),
        [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          done_loading.Notify();
        });

    ASSERT_SUCCESS(result);
    done_loading.WaitForNotification();
  }

  {
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id_2";
    load_request->version_string = "v2";
    load_request->js = R"(test = (s) => s + " Some string 2";)";

    absl::Notification done_loading;

    auto result = dispatcher.Dispatch(
        std::move(load_request),
        [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          done_loading.Notify();
        });

    ASSERT_SUCCESS(result);
    done_loading.WaitForNotification();
  }

  // We kill the worker so we expect the first request right after to fail
  auto worker = worker_pool.GetWorker(0);
  ASSERT_SUCCESS(worker.result());
  (*worker)->Terminate();

  {
    auto execute_request = std::make_unique<InvocationStrRequest<>>();
    execute_request->id = "some_id";
    execute_request->version_string = "v1";
    execute_request->handler_name = "test";
    execute_request->input.push_back(R"("Hello")");

    absl::Notification done_executing;
    auto result = dispatcher.Dispatch(
        std::move(execute_request),
        [&done_executing](
            std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          // This request failed but it should have caused the restart of the
          // worker so subsequent requests should work.
          EXPECT_FALSE(resp->ok());
          done_executing.Notify();
        });

    ASSERT_SUCCESS(result);
    done_executing.WaitForNotification();
  }

  // Subsequent requests should succeed

  for (int i = 0; i < 10; i++) {
    {
      auto execute_request = std::make_unique<InvocationStrRequest<>>();
      execute_request->id = "some_id";
      execute_request->version_string = "v1";
      execute_request->handler_name = "test";
      execute_request->input.push_back(R"("Hello 1")");

      absl::Notification done_executing;
      auto result = dispatcher.Dispatch(
          std::move(execute_request),
          [&done_executing](
              std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
            EXPECT_TRUE(resp->ok());
            EXPECT_THAT((*resp)->resp, StrEq(R"("Hello 1 Some string 1")"));
            done_executing.Notify();
          });

      ASSERT_SUCCESS(result);
      done_executing.WaitForNotification();
    }
    {
      auto execute_request = std::make_unique<InvocationStrRequest<>>();
      execute_request->id = "some_id_2";
      execute_request->version_string = "v2";
      execute_request->handler_name = "test";
      execute_request->input.push_back(R"("Hello 2")");

      absl::Notification done_executing;
      auto result = dispatcher.Dispatch(
          std::move(execute_request),
          [&done_executing](
              std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
            EXPECT_TRUE(resp->ok());
            EXPECT_THAT((*resp)->resp, StrEq(R"("Hello 2 Some string 2")"));
            done_executing.Notify();
          });

      ASSERT_SUCCESS(result);
      done_executing.WaitForNotification();
    }
  }
}

TEST(DispatcherTest, ShouldBeAbleToLoadMoreVersionsAfterWorkerCrash) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  // Only one worker in the pool
  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 10, 5);

  {
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id";
    load_request->version_string = "v1";
    load_request->js = R"(test = (s) => s + " Some string 1";)";

    absl::Notification done_loading;

    auto result = dispatcher.Dispatch(
        std::move(load_request),
        [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          done_loading.Notify();
        });
    ASSERT_SUCCESS(result);

    done_loading.WaitForNotification();
  }

  {
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id_2";
    load_request->version_string = "v2";
    load_request->js = R"(test = (s) => s + " Some string 2";)";

    absl::Notification done_loading;

    auto result = dispatcher.Dispatch(
        std::move(load_request),
        [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          EXPECT_TRUE(resp->ok());
          done_loading.Notify();
        });

    ASSERT_SUCCESS(result);
    done_loading.WaitForNotification();
  }

  // We kill the worker so we expect the first request right after to fail
  auto worker = worker_pool.GetWorker(0);
  ASSERT_SUCCESS(worker.result());
  (*worker)->Terminate();

  for (int i = 0; i < 2; i++) {
    // The first load should fail as the worker had died
    auto load_request = std::make_unique<CodeObject>();
    load_request->id = "some_id_3";
    load_request->version_string = "v3";
    load_request->js = R"(test = (s) => s + " Some string 3";)";

    absl::Notification done_loading;
    auto result = dispatcher.Dispatch(
        std::move(load_request),
        [&done_loading,
         i](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
          if (i == 0) {
            // Failed
            EXPECT_FALSE(resp->ok());
          } else {
            EXPECT_TRUE(resp->ok());
          }

          done_loading.Notify();
        });

    ASSERT_SUCCESS(result);
    done_loading.WaitForNotification();
  }

  // Execute all versions, those loaded before and after the worker crash
  for (int i = 0; i < 10; i++) {
    {
      auto execute_request = std::make_unique<InvocationStrRequest<>>();
      execute_request->id = "some_id";
      execute_request->version_string = "v1";
      execute_request->handler_name = "test";
      execute_request->input.push_back("\"Hello 1\"");

      absl::Notification done_executing;
      auto result = dispatcher.Dispatch(
          std::move(execute_request),
          [&done_executing](
              std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
            EXPECT_TRUE(resp->ok());
            EXPECT_THAT((*resp)->resp, StrEq("\"Hello 1 Some string 1\""));
            done_executing.Notify();
          });

      ASSERT_SUCCESS(result);
      done_executing.WaitForNotification();
    }
    {
      auto execute_request = std::make_unique<InvocationStrRequest<>>();
      execute_request->id = "some_id_2";
      execute_request->version_string = "v2";
      execute_request->handler_name = "test";
      execute_request->input.push_back("\"Hello 2\"");

      absl::Notification done_executing;
      auto result = dispatcher.Dispatch(
          std::move(execute_request),
          [&done_executing](
              std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
            EXPECT_TRUE(resp->ok());
            EXPECT_THAT((*resp)->resp, StrEq("\"Hello 2 Some string 2\""));
            done_executing.Notify();
          });

      ASSERT_SUCCESS(result);
      done_executing.WaitForNotification();
    }
    {
      auto execute_request = std::make_unique<InvocationStrRequest<>>();
      execute_request->id = "some_id_3";
      execute_request->version_string = "v3";
      execute_request->handler_name = "test";
      execute_request->input.push_back("\"Hello 3\"");

      absl::Notification done_executing;
      auto result = dispatcher.Dispatch(
          std::move(execute_request),
          [&done_executing](
              std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
            EXPECT_TRUE(resp->ok());
            EXPECT_THAT((*resp)->resp, StrEq("\"Hello 3 Some string 3\""));
            done_executing.Notify();
          });

      ASSERT_SUCCESS(result);
      done_executing.WaitForNotification();
    }
  }
}

TEST(DispatcherTest, ShouldFailIfCodeVersionCacheSizeIsZero) {
  AsyncExecutor async_executor(1, 10);
  WorkerPoolApiSapi worker_pool({});
  constexpr size_t max_pending_requests = 10;
  constexpr size_t code_version_cache_size = 0;

  EXPECT_DEATH(Dispatcher(&async_executor, &worker_pool, max_pending_requests,
                          code_version_cache_size),
               "code_version_cache_size cannot be zero");
}

TEST(DispatcherTest, ShouldFailIfMaxPendingRequestsIsZero) {
  AsyncExecutor async_executor(1, 10);
  WorkerPoolApiSapi worker_pool({});
  constexpr size_t max_pending_requests = 0;
  constexpr size_t code_version_cache_size = 5;

  EXPECT_DEATH(Dispatcher(&async_executor, &worker_pool, max_pending_requests,
                          code_version_cache_size),
               "max_pending_requests cannot be zero");
}

TEST(DispatcherTest, CanRunCodeWithTreatInputAsByteStr) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs = {CreateWorkerApiSapiConfig()};

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool,
                        /*max_pending_requests=*/10,
                        /*code_version_cache_size=*/5);

  auto load_request = std::make_unique<CodeObject>(CodeObject{
      .id = "some_id",
      .version_string = "v1",
      .js = "function test(input) { return input + \" Some string\"; }",
  });

  absl::Notification done_loading;

  auto result = dispatcher.Dispatch(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        done_loading.Notify();
      });
  ASSERT_SUCCESS(result);

  done_loading.WaitForNotification();

  auto execute_request =
      std::make_unique<InvocationStrViewRequest<>>(InvocationStrViewRequest<>{
          .id = "some_id",
          .version_string = "v1",
          .handler_name = "test",
          .input = {R"("Hello")"},
          .treat_input_as_byte_str = true,
      });

  absl::Notification done_executing;

  result = dispatcher.Dispatch(
      std::move(execute_request),
      [&done_executing](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        EXPECT_THAT((*resp)->resp, StrEq(R"("Hello" Some string)"));
        done_executing.Notify();
      });

  ASSERT_SUCCESS(result);

  done_executing.WaitForNotification();
}

TEST(DispatcherTest, RaisesErrorWithMoreThanOneInputWithTreatInputAsByteStr) {
  AsyncExecutor async_executor(1, 10);

  std::vector<WorkerApiSapiConfig> configs;
  configs.push_back(CreateWorkerApiSapiConfig());

  WorkerPoolApiSapi worker_pool(configs);
  AutoInitRunStop for_async_executor(async_executor);
  AutoInitRunStop for_worker_pool(worker_pool);

  Dispatcher dispatcher(&async_executor, &worker_pool, 1, 5);

  auto load_request = std::make_unique<CodeObject>(CodeObject{
      .id = "some_id",
      .version_string = "v1",
      .js = "function test(input, input2) { return input + input2 + \" Some "
            "string\"; }",
  });

  absl::Notification done_loading;

  auto result = dispatcher.Dispatch(
      std::move(load_request),
      [&done_loading](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {
        EXPECT_TRUE(resp->ok());
        done_loading.Notify();
      });
  ASSERT_SUCCESS(result);

  done_loading.WaitForNotification();

  // Multiple inputs with treat_input_as_byte_str as true.
  auto execute_request =
      std::make_unique<InvocationStrViewRequest<>>(InvocationStrViewRequest<>{
          .id = "some_id",
          .version_string = "v1",
          .handler_name = "test",
          .input = {R"("Hello")", R"("Hello 2")"},
          .treat_input_as_byte_str = true,
      });

  result = dispatcher.Dispatch(
      std::move(execute_request),
      [](std::unique_ptr<absl::StatusOr<ResponseObject>> resp) {});

  EXPECT_THAT(
      result,
      core::test::ResultIs(FailureExecutionResult(
          SC_ROMA_DISPATCHER_DISPATCH_DISALLOWED_MULTIPLE_BYTE_STR_INPUTS)));
}
}  // namespace google::scp::roma::sandbox::dispatcher::test
