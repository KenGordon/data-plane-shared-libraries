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

#ifndef CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_MOCK_MOCK_KMS_CLIENT_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_MOCK_MOCK_KMS_CLIENT_PROVIDER_H_

#include <gmock/gmock.h>

#include <memory>
#include <vector>

#include "src/core/interface/async_context.h"
#include "src/cpio/client_providers/interface/kms_client_provider_interface.h"
#include "src/public/core/interface/execution_result.h"

namespace google::scp::cpio::client_providers::mock {
class MockKmsClientProvider : public KmsClientProviderInterface {
 public:
  MOCK_METHOD(absl::Status, Decrypt,
              ((core::AsyncContext<
                  google::cmrt::sdk::kms_service::v1::DecryptRequest,
                  google::cmrt::sdk::kms_service::v1::DecryptResponse>&)),
              (noexcept, override));
};
}  // namespace google::scp::cpio::client_providers::mock

#endif  // CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_MOCK_MOCK_KMS_CLIENT_PROVIDER_H_
