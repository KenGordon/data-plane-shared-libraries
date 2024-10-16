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
#include <iostream>
#include <memory>
#include <string>

#include "absl/synchronization/notification.h"
#include "public/core/interface/errors.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/cpio.h"
#include "public/cpio/interface/parameter_client/parameter_client_interface.h"
#include "public/cpio/interface/type_def.h"
#include "public/cpio/proto/parameter_service/v1/parameter_service.pb.h"

using google::cmrt::sdk::parameter_service::v1::GetParameterRequest;
using google::cmrt::sdk::parameter_service::v1::GetParameterResponse;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::GetErrorMessage;
using google::scp::core::SuccessExecutionResult;
using google::scp::cpio::Cpio;
using google::scp::cpio::CpioOptions;
using google::scp::cpio::LogOption;
using google::scp::cpio::ParameterClientFactory;
using google::scp::cpio::ParameterClientInterface;
using google::scp::cpio::ParameterClientOptions;

static constexpr char kTestParameterName[] = "test_parameter";

int main(int argc, char* argv[]) {
  CpioOptions cpio_options;
  cpio_options.log_option = LogOption::kConsoleLog;
  auto result = Cpio::InitCpio(cpio_options);
  if (!result.Successful()) {
    std::cout << "Failed to initialize CPIO: "
              << GetErrorMessage(result.status_code) << std::endl;
  }

  ParameterClientOptions parameter_client_options;
  auto parameter_client =
      ParameterClientFactory::Create(std::move(parameter_client_options));
  result = parameter_client->Init();
  if (!result.Successful()) {
    std::cout << "Cannot init parameter client!"
              << GetErrorMessage(result.status_code) << std::endl;
    return 0;
  }
  result = parameter_client->Run();
  if (!result.Successful()) {
    std::cout << "Cannot run parameter client!"
              << GetErrorMessage(result.status_code) << std::endl;
    return 0;
  }

  absl::Notification finished;
  GetParameterRequest get_parameter_request;
  get_parameter_request.set_parameter_name(kTestParameterName);
  result = parameter_client->GetParameter(
      std::move(get_parameter_request),
      [&](const ExecutionResult result, GetParameterResponse response) {
        if (!result.Successful()) {
          std::cout << "GetParameter failed: "
                    << GetErrorMessage(result.status_code) << std::endl;
        } else {
          std::cout << "GetParameter succeeded, and parameter is: "
                    << response.parameter_value() << std::endl;
        }
        finished.Notify();
      });
  if (!result.Successful()) {
    std::cout << "GetParameter failed immediately: "
              << GetErrorMessage(result.status_code) << std::endl;
  }
  finished.WaitForNotificationWithTimeout(absl::Seconds(10));

  result = parameter_client->Stop();
  if (!result.Successful()) {
    std::cout << "Cannot stop parameter client!"
              << GetErrorMessage(result.status_code) << std::endl;
  }

  result = Cpio::ShutdownCpio(cpio_options);
  if (!result.Successful()) {
    std::cout << "Failed to shutdown CPIO: "
              << GetErrorMessage(result.status_code) << std::endl;
  }
}
