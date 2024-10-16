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

#include "scp/cc/public/cpio/validator/parameter_client_validator.h"

#include <memory>
#include <utility>

#include "absl/log/log.h"
#include "absl/synchronization/notification.h"
#include "scp/cc/public/core/interface/errors.h"
#include "scp/cc/public/core/interface/execution_result.h"
#include "scp/cc/public/cpio/interface/parameter_client/parameter_client_interface.h"
#include "scp/cc/public/cpio/interface/parameter_client/type_def.h"
#include "scp/cc/public/cpio/proto/parameter_service/v1/parameter_service.pb.h"
#include "scp/cc/public/cpio/validator/proto/validator_config.pb.h"

namespace google::scp::cpio::validator {

namespace {

using google::cmrt::sdk::parameter_service::v1::GetParameterRequest;
using google::cmrt::sdk::parameter_service::v1::GetParameterResponse;
using google::scp::core::AsyncContext;
using google::scp::cpio::ParameterClientFactory;
using google::scp::cpio::validator::proto::GetParameterConfig;
}  // namespace

void RunGetParameterValidator(std::string_view name,
                              const GetParameterConfig& get_parameter_config) {
  if (get_parameter_config.parameter_name().empty()) {
    std::cout << "[ FAILURE ] " << name << " No parameter name provided.";
    return;
  }
  google::scp::cpio::ParameterClientOptions parameter_client_options;
  std::unique_ptr<google::scp::cpio::ParameterClientInterface>
      parameter_client =
          ParameterClientFactory::Create(std::move(parameter_client_options));
  if (google::scp::core::ExecutionResult result = parameter_client->Init();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << google::scp::core::GetErrorMessage(result.status_code)
              << std::endl;
    return;
  }

  if (google::scp::core::ExecutionResult result = parameter_client->Run();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << google::scp::core::GetErrorMessage(result.status_code)
              << std::endl;
    return;
  }
  absl::Notification finished;
  GetParameterRequest get_parameter_request;
  get_parameter_request.set_parameter_name(
      get_parameter_config.parameter_name());
  google::scp::core::ExecutionResult result = parameter_client->GetParameter(
      std::move(get_parameter_request),
      [&finished, &name](const google::scp::core::ExecutionResult result,
                         GetParameterResponse response) {
        if (!result.Successful()) {
          std::cout << "[ FAILURE ] " << name << " "
                    << google::scp::core::GetErrorMessage(result.status_code)
                    << std::endl;
        } else {
          std::cout << "[ SUCCESS ] " << name << std::endl;
          LOG(INFO) << " Parameter value: " << response.parameter_value();
        }
        finished.Notify();
      });
  if (!result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << google::scp::core::GetErrorMessage(result.status_code)
              << std::endl;
  }
  finished.WaitForNotification();
  if (google::scp::core::ExecutionResult result = parameter_client->Stop();
      !result.Successful()) {
    std::cout << "[ FAILURE ] " << name << " "
              << google::scp::core::GetErrorMessage(result.status_code)
              << std::endl;
  }
}
};  // namespace google::scp::cpio::validator
