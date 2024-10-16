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

#include "test_aws_instance_client_provider.h"

#include <string>
#include <string_view>
#include <vector>

#include "absl/strings/str_format.h"
#include "public/core/interface/execution_result.h"

using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;

namespace {
constexpr std::string_view kAwsResourceNameFormat =
    R"(arn:aws:ec2:%s:%s:instance/%s)";
}  // namespace

namespace google::scp::cpio::client_providers {

ExecutionResult
TestAwsInstanceClientProvider::GetCurrentInstanceResourceNameSync(
    std::string& resource_name) noexcept {
  resource_name =
      absl::StrFormat(kAwsResourceNameFormat, test_options_->region,
                      test_options_->project_id, test_options_->instance_id);
  return SuccessExecutionResult();
}

}  // namespace google::scp::cpio::client_providers
