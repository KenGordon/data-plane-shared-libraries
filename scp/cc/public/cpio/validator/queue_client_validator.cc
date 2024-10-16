// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "scp/cc/public/cpio/validator/queue_client_validator.h"

#include <memory>
#include <utility>

#include "absl/log/log.h"
#include "absl/synchronization/notification.h"
#include "cpio/client_providers/global_cpio/src/global_cpio.h"
#include "scp/cc/core/interface/async_context.h"
#include "scp/cc/public/core/interface/errors.h"
#include "scp/cc/public/core/interface/execution_result.h"
#include "scp/cc/public/cpio/proto/queue_service/v1/queue_service.pb.h"
#include "scp/cc/public/cpio/validator/proto/validator_config.pb.h"

namespace google::scp::cpio::validator {

namespace {
using google::cmrt::sdk::queue_service::v1::EnqueueMessageRequest;
using google::cmrt::sdk::queue_service::v1::EnqueueMessageResponse;
using google::cmrt::sdk::queue_service::v1::GetTopMessageRequest;
using google::cmrt::sdk::queue_service::v1::GetTopMessageResponse;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutorInterface;
using google::scp::cpio::client_providers::GlobalCpio;
using google::scp::cpio::client_providers::InstanceClientProviderInterface;
using google::scp::cpio::client_providers::QueueClientOptions;
using google::scp::cpio::validator::proto::EnqueueMessageConfig;

inline constexpr std::string_view kQueueName = "queue_service_test_queue";
}  // namespace

void RunEnqueueMessageValidator(
    std::string_view name, const EnqueueMessageConfig& enqueue_message_config) {
  if (enqueue_message_config.message_body().empty()) {
    std::cout << "[ FAILURE ]  " << name << " No message body provided."
              << std::endl;
    return;
  }

  std::shared_ptr<InstanceClientProviderInterface> instance_client;
  std::shared_ptr<AsyncExecutorInterface> cpu_async_executor;
  std::shared_ptr<AsyncExecutorInterface> io_async_executor;

  if (auto res = GlobalCpio::GetGlobalCpio()->GetInstanceClientProvider(
          instance_client);
      !res) {
    std::cout << "[ FAILURE ] Unable to get Instance Client Provider."
              << std::endl;
    return;
  }

  if (auto res =
          GlobalCpio::GetGlobalCpio()->GetCpuAsyncExecutor(cpu_async_executor);
      !res) {
    std::cout << "[ FAILURE ] Unable to get Cpu Async Executor." << std::endl;
    return;
  }

  if (auto res =
          GlobalCpio::GetGlobalCpio()->GetIoAsyncExecutor(io_async_executor);
      !res) {
    std::cout << "[ FAILURE ] Unable to get Io Async Executor." << std::endl;
    return;
  }

  auto options = std::make_shared<QueueClientOptions>();
  options->queue_name = kQueueName;
  auto queue_client =
      google::scp::cpio::client_providers::QueueClientProviderFactory::Create(
          options, instance_client, cpu_async_executor, io_async_executor);

  if (google::scp::core::ExecutionResult result = queue_client->Init();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
    return;
  }
  if (google::scp::core::ExecutionResult result = queue_client->Run();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
    return;
  }
  // EnqueueMessage.
  absl::Notification finished;
  google::scp::core::ExecutionResult result;
  auto enqueue_message_request = std::make_shared<EnqueueMessageRequest>();
  enqueue_message_request->set_message_body(
      enqueue_message_config.message_body());
  AsyncContext<EnqueueMessageRequest, EnqueueMessageResponse>
      enqueue_message_context(
          std::move(enqueue_message_request),
          [&result, &finished, &name](auto& context) {
            result = context.result;
            if (result.Successful()) {
              std::cout << "[ SUCCESS ] " << name << " " << std::endl;
              LOG(INFO) << context.response->DebugString() << std::endl;
            }
            finished.Notify();
          });
  if (auto enqueue_message_result =
          queue_client->EnqueueMessage(enqueue_message_context);
      !enqueue_message_result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(
                     enqueue_message_result.status_code)
              << std::endl;
    return;
  }
  finished.WaitForNotification();
  if (!result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
    return;
  }
  if (auto result = queue_client->Stop(); !result.Successful()) {
    std::cout << " [ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
  }
}

void RunGetTopMessageValidator(std::string_view name) {
  std::shared_ptr<InstanceClientProviderInterface> instance_client;
  std::shared_ptr<AsyncExecutorInterface> cpu_async_executor;
  std::shared_ptr<AsyncExecutorInterface> io_async_executor;

  if (auto res = GlobalCpio::GetGlobalCpio()->GetInstanceClientProvider(
          instance_client);
      !res) {
    std::cout << "[ FAILURE ] Unable to get Instance Client Provider."
              << std::endl;
    return;
  }

  if (auto res =
          GlobalCpio::GetGlobalCpio()->GetCpuAsyncExecutor(cpu_async_executor);
      !res) {
    std::cout << "[ FAILURE ] Unable to get Cpu Async Executor." << std::endl;
    return;
  }

  if (auto res =
          GlobalCpio::GetGlobalCpio()->GetIoAsyncExecutor(io_async_executor);
      !res) {
    std::cout << "[ FAILURE ] Unable to get Io Async Executor." << std::endl;
    return;
  }

  auto options = std::make_shared<QueueClientOptions>();
  options->queue_name = kQueueName;
  auto queue_client =
      google::scp::cpio::client_providers::QueueClientProviderFactory::Create(
          options, instance_client, cpu_async_executor, io_async_executor);

  if (google::scp::core::ExecutionResult result = queue_client->Init();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
    return;
  }
  if (google::scp::core::ExecutionResult result = queue_client->Run();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
    return;
  }
  // GetTopMessage.
  absl::Notification finished;
  google::scp::core::ExecutionResult result;
  auto get_top_message_request = std::make_shared<GetTopMessageRequest>();
  AsyncContext<GetTopMessageRequest, GetTopMessageResponse>
      get_top_message_context(
          std::move(get_top_message_request),
          [&result, &finished, &name](auto& context) {
            result = context.result;
            if (result.Successful()) {
              std::cout << "[ SUCCESS ] " << name << " " << std::endl;
              LOG(INFO) << "Message Body: " << context.response->message_body()
                        << std::endl;
            }
            finished.Notify();
          });
  if (auto get_top_message_result =
          queue_client->GetTopMessage(get_top_message_context);
      !get_top_message_result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(
                     get_top_message_result.status_code)
              << std::endl;
    return;
  }
  finished.WaitForNotification();
  if (!result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
    return;
  }
  if (auto result = queue_client->Stop(); !result.Successful()) {
    std::cout << " [ FAILURE ] " << name << " "
              << core::errors::GetErrorMessage(result.status_code) << std::endl;
  }
}
}  // namespace google::scp::cpio::validator
