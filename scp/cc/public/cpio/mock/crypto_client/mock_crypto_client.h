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

#ifndef PUBLIC_CPIO_MOCK_CRYPTO_CLIENT_MOCK_CRYPTO_CLIENT_H_
#define PUBLIC_CPIO_MOCK_CRYPTO_CLIENT_MOCK_CRYPTO_CLIENT_H_

#include <gmock/gmock.h>

#include <memory>

#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/crypto_client/crypto_client_interface.h"

namespace google::scp::cpio {
class MockCryptoClient : public CryptoClientInterface {
 public:
  MockCryptoClient() {
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

  MOCK_METHOD(
      core::ExecutionResult, HpkeEncrypt,
      (cmrt::sdk::crypto_service::v1::HpkeEncryptRequest request,
       Callback<cmrt::sdk::crypto_service::v1::HpkeEncryptResponse> callback),
      (noexcept, override));

  MOCK_METHOD(
      core::ExecutionResult, HpkeDecrypt,
      (cmrt::sdk::crypto_service::v1::HpkeDecryptRequest request,
       Callback<cmrt::sdk::crypto_service::v1::HpkeDecryptResponse> callback),
      (noexcept, override));

  MOCK_METHOD(
      core::ExecutionResult, AeadEncrypt,
      (cmrt::sdk::crypto_service::v1::AeadEncryptRequest request,
       Callback<cmrt::sdk::crypto_service::v1::AeadEncryptResponse> callback),
      (noexcept, override));

  MOCK_METHOD(
      core::ExecutionResult, AeadDecrypt,
      (cmrt::sdk::crypto_service::v1::AeadDecryptRequest request,
       Callback<cmrt::sdk::crypto_service::v1::AeadDecryptResponse> callback),
      (noexcept, override));
};

}  // namespace google::scp::cpio

#endif  // PUBLIC_CPIO_MOCK_CRYPTO_CLIENT_MOCK_CRYPTO_CLIENT_H_
