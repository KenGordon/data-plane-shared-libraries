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

#ifndef PUBLIC_CPIO_MOCK_PARAMETER_CLIENT_MOCK_PARAMETER_CLIENT_H_
#define PUBLIC_CPIO_MOCK_PARAMETER_CLIENT_MOCK_PARAMETER_CLIENT_H_

#include <gmock/gmock.h>

#include <memory>

#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/interface/parameter_client/parameter_client_interface.h"

namespace google::scp::cpio {
class MockParameterClient : public ParameterClientInterface {
 public:
  MockParameterClient() {
    ON_CALL(*this, Init)
        .WillByDefault(testing::Return(core::SuccessExecutionResult()));
    ON_CALL(*this, Run)
        .WillByDefault(testing::Return(core::SuccessExecutionResult()));
    ON_CALL(*this, Stop)
        .WillByDefault(testing::Return(core::SuccessExecutionResult()));
  }

  MOCK_METHOD(core::ExecutionResult, Init, (), (noexcept, override));
  MOCK_METHOD(core::ExecutionResult, Run, (), (noexcept, override));
  MOCK_METHOD(core::ExecutionResult, Stop, (), (noexcept, override));

  MOCK_METHOD(core::ExecutionResult, GetParameter,
              (cmrt::sdk::parameter_service::v1::GetParameterRequest request,
               Callback<cmrt::sdk::parameter_service::v1::GetParameterResponse>
                   callback),
              (noexcept, override));
};

}  // namespace google::scp::cpio

#endif  // PUBLIC_CPIO_MOCK_PARAMETER_CLIENT_MOCK_PARAMETER_CLIENT_H_
