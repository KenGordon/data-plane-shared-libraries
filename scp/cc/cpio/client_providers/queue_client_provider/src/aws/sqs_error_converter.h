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

#ifndef CPIO_CLIENT_PROVIDERS_QUEUE_CLIENT_PROVIDER_SRC_AWS_SQS_ERROR_CONVERTER_H_
#define CPIO_CLIENT_PROVIDERS_QUEUE_CLIENT_PROVIDER_SRC_AWS_SQS_ERROR_CONVERTER_H_

#include <aws/sqs/SQSErrors.h>

#include "public/core/interface/execution_result.h"

#include "error_codes.h"

namespace google::scp::cpio::client_providers {
class SqsErrorConverter {
 public:
  /**
   * @brief Converts SQS Error to ExecutionResult with failure status
   *
   * @param error The SQS error comes from AWS.
   *
   * @return core::FailureExecutionResult The converted result of the operation.
   */
  static core::FailureExecutionResult ConvertSqsError(
      const Aws::SQS::SQSErrors& error);
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_QUEUE_CLIENT_PROVIDER_SRC_AWS_SQS_ERROR_CONVERTER_H_
