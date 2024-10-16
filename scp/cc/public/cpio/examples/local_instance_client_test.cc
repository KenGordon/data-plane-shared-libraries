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

#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include "absl/functional/bind_front.h"
#include "absl/synchronization/notification.h"
#include "public/core/interface/errors.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/cpio.h"
#include "public/cpio/interface/instance_client/instance_client_interface.h"
#include "public/cpio/interface/type_def.h"
#include "public/cpio/proto/instance_service/v1/instance_service.pb.h"
#include "public/cpio/test/global_cpio/test_lib_cpio.h"

using google::cmrt::sdk::instance_service::v1::
    GetCurrentInstanceResourceNameRequest;
using google::cmrt::sdk::instance_service::v1::
    GetCurrentInstanceResourceNameResponse;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::GetErrorMessage;
using google::scp::core::SuccessExecutionResult;
using google::scp::cpio::InstanceClientFactory;
using google::scp::cpio::InstanceClientInterface;
using google::scp::cpio::InstanceClientOptions;
using google::scp::cpio::LogOption;
using google::scp::cpio::TestCpioOptions;
using google::scp::cpio::TestLibCpio;

static constexpr char kRegion[] = "us-east-1";
static constexpr char kInstanceId[] = "i-1234";

std::unique_ptr<InstanceClientInterface> instance_client;

void GetCurrentInstanceResourceNameCallback(
    absl::Notification& finished, ExecutionResult result,
    GetCurrentInstanceResourceNameResponse get_resource_name_response) {
  if (!result.Successful()) {
    std::cout << "Hpke encrypt failure!" << GetErrorMessage(result.status_code)
              << std::endl;
    return;
  }

  std::cout << "GetCurrentInstanceResourceName succeeded, and the "
               "instance resource name is: "
            << get_resource_name_response.instance_resource_name() << std::endl;
}

int main(int argc, char* argv[]) {
  TestCpioOptions cpio_options;
  cpio_options.log_option = LogOption::kConsoleLog;
  cpio_options.region = kRegion;
  cpio_options.instance_id = kInstanceId;
  auto result = TestLibCpio::InitCpio(cpio_options);
  if (!result.Successful()) {
    std::cout << "Failed to initialize CPIO: "
              << GetErrorMessage(result.status_code) << std::endl;
  }

  InstanceClientOptions instance_client_options;
  instance_client =
      InstanceClientFactory::Create(std::move(instance_client_options));
  result = instance_client->Init();
  if (!result.Successful()) {
    std::cout << "Cannot init instance client!"
              << GetErrorMessage(result.status_code) << std::endl;
    return 0;
  }
  result = instance_client->Run();
  if (!result.Successful()) {
    std::cout << "Cannot run instance client!"
              << GetErrorMessage(result.status_code) << std::endl;
    return 0;
  }

  absl::Notification finished;
  result = instance_client->GetCurrentInstanceResourceName(
      GetCurrentInstanceResourceNameRequest(),
      absl::bind_front(GetCurrentInstanceResourceNameCallback,
                       std::ref(finished)));

  if (!result.Successful()) {
    std::cout << "GetCurrentInstanceResourceName failed immediately: "
              << GetErrorMessage(result.status_code) << std::endl;
  }
  finished.WaitForNotificationWithTimeout(absl::Seconds(3));

  result = instance_client->Stop();
  if (!result.Successful()) {
    std::cout << "Cannot stop instance client!"
              << GetErrorMessage(result.status_code) << std::endl;
  }

  result = TestLibCpio::ShutdownCpio(cpio_options);
  if (!result.Successful()) {
    std::cout << "Failed to shutdown CPIO: "
              << GetErrorMessage(result.status_code) << std::endl;
  }
}
