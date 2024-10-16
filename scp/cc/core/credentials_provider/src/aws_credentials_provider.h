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

#ifndef CORE_CREDENTIALS_PROVIDER_SRC_AWS_CREDENTIALS_PROVIDER_H_
#define CORE_CREDENTIALS_PROVIDER_SRC_AWS_CREDENTIALS_PROVIDER_H_

#include <memory>

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>

#include "core/interface/credentials_provider_interface.h"

namespace google::scp::core {

class AwsCredentialsProvider : public CredentialsProviderInterface {
 public:
  AwsCredentialsProvider()
      : credentials_provider_(
            std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>()) {
  }

  ExecutionResult Init() noexcept override;

  ExecutionResult GetCredentials(
      AsyncContext<GetCredentialsRequest, GetCredentialsResponse>&
          get_credentials_context) noexcept override;

 protected:
  std::shared_ptr<Aws::Auth::DefaultAWSCredentialsProviderChain>
      credentials_provider_;
};
}  // namespace google::scp::core

#endif  // CORE_CREDENTIALS_PROVIDER_SRC_AWS_CREDENTIALS_PROVIDER_H_
