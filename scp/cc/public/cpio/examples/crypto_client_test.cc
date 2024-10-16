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
#include "public/cpio/interface/crypto_client/crypto_client_interface.h"
#include "public/cpio/interface/crypto_client/type_def.h"
#include "public/cpio/interface/type_def.h"

using google::cmrt::sdk::crypto_service::v1::AeadDecryptRequest;
using google::cmrt::sdk::crypto_service::v1::AeadDecryptResponse;
using google::cmrt::sdk::crypto_service::v1::AeadEncryptRequest;
using google::cmrt::sdk::crypto_service::v1::AeadEncryptResponse;
using google::cmrt::sdk::crypto_service::v1::HpkeAead;
using google::cmrt::sdk::crypto_service::v1::HpkeDecryptRequest;
using google::cmrt::sdk::crypto_service::v1::HpkeDecryptResponse;
using google::cmrt::sdk::crypto_service::v1::HpkeEncryptRequest;
using google::cmrt::sdk::crypto_service::v1::HpkeEncryptResponse;
using google::scp::core::ExecutionResult;
using google::scp::core::GetErrorMessage;
using google::scp::core::SuccessExecutionResult;
using google::scp::cpio::Cpio;
using google::scp::cpio::CpioOptions;
using google::scp::cpio::CryptoClientFactory;
using google::scp::cpio::CryptoClientInterface;
using google::scp::cpio::CryptoClientOptions;
using google::scp::cpio::LogOption;

constexpr char kPublicKey[] = "testpublickey==";
constexpr char kPrivateKey[] = "testprivatekey=";
constexpr char kSharedInfo[] = "shared_info";
constexpr char kRequestPayload[] = "abcdefg";
constexpr char kResponsePayload[] = "hijklmn";

std::unique_ptr<CryptoClientInterface> crypto_client;

void AeadDecryptCallback(absl::Notification& finished, ExecutionResult result,
                         AeadDecryptResponse aead_decrypt_response) {
  finished.Notify();
  if (result.Successful()) {
    std::cout << "Aead decrypt success! Decrypted response payload: "
              << aead_decrypt_response.payload() << std::endl;
  } else {
    std::cout << "Aead decrypt failure!" << GetErrorMessage(result.status_code)
              << std::endl;
  }
}

void AeadEncryptCallback(absl::Notification& finished, std::string& secret,
                         ExecutionResult result,
                         AeadEncryptResponse aead_encrypt_response) {
  if (result.Successful()) {
    std::cout << "Aead encrypt success!" << std::endl;
    AeadDecryptRequest aead_decrypt_request;
    aead_decrypt_request.set_shared_info(std::string(kSharedInfo));
    aead_decrypt_request.set_secret(secret);
    aead_decrypt_request.mutable_encrypted_data()->set_ciphertext(
        aead_encrypt_response.encrypted_data().ciphertext());
    crypto_client->AeadDecrypt(
        std::move(aead_decrypt_request),
        absl::bind_front(AeadDecryptCallback, std::ref(finished)));
  } else {
    finished.Notify();
    std::cout << "Aead encrypt failure!" << GetErrorMessage(result.status_code)
              << std::endl;
  }
}

void HpkeDecryptCallback(bool is_bidirectional, absl::Notification& finished,
                         ExecutionResult result,
                         HpkeDecryptResponse hpke_decrypt_response) {
  if (result.Successful()) {
    std::cout << "Hpke decrypt success! Decrypted request Payload: "
              << hpke_decrypt_response.payload() << std::endl;
    if (is_bidirectional) {
      std::cout << "Response payload to be encrypted using Aead: "
                << kResponsePayload << std::endl;
      AeadEncryptRequest aead_encrypt_request;
      aead_encrypt_request.set_shared_info(std::string(kSharedInfo));
      aead_encrypt_request.set_payload(std::string(kResponsePayload));
      auto secret = hpke_decrypt_response.secret();
      aead_encrypt_request.set_secret(secret);
      crypto_client->AeadEncrypt(
          std::move(aead_encrypt_request),
          absl::bind_front(AeadEncryptCallback, std::ref(finished), secret));
    } else {
      finished.Notify();
    }
  } else {
    finished.Notify();
    std::cout << "Hpke decrypt failure! " << GetErrorMessage(result.status_code)
              << std::endl;
  }
}

void HpkeEncryptCallback(bool is_bidirectional, absl::Notification& finished,
                         ExecutionResult result,
                         HpkeEncryptResponse hpke_encrypt_response) {
  if (result.Successful()) {
    std::cout << "Hpke encrypt success!" << std::endl;
    HpkeDecryptRequest hpke_decrypt_request;
    hpke_decrypt_request.mutable_private_key()->set_private_key(kPrivateKey);
    hpke_decrypt_request.set_shared_info(std::string(kSharedInfo));
    hpke_decrypt_request.set_is_bidirectional(is_bidirectional);
    hpke_decrypt_request.mutable_encrypted_data()->set_ciphertext(
        hpke_encrypt_response.encrypted_data().ciphertext());
    hpke_decrypt_request.mutable_encrypted_data()->set_key_id(
        hpke_encrypt_response.encrypted_data().key_id());
    crypto_client->HpkeDecrypt(
        std::move(hpke_decrypt_request),
        absl::bind_front(HpkeDecryptCallback, is_bidirectional,
                         std::ref(finished)));
  } else {
    std::cout << "Hpke encrypt failure!" << GetErrorMessage(result.status_code)
              << std::endl;
  }
}

int main(int argc, char* argv[]) {
  bool is_bidirectional = false;
  if (argc > 1) {
    is_bidirectional = std::string(argv[1]) == "true";
  }

  CpioOptions cpio_options;
  cpio_options.log_option = LogOption::kConsoleLog;
  auto result = Cpio::InitCpio(cpio_options);
  if (!result.Successful()) {
    std::cout << "Failed to initialize CPIO: "
              << GetErrorMessage(result.status_code) << std::endl;
  }

  CryptoClientOptions crypto_client_options;

  crypto_client = CryptoClientFactory::Create(std::move(crypto_client_options));
  result = crypto_client->Init();
  if (!result.Successful()) {
    std::cout << "Cannot init crypto client!"
              << GetErrorMessage(result.status_code) << std::endl;
    return 0;
  }
  result = crypto_client->Run();
  if (!result.Successful()) {
    std::cout << "Cannot run crypto client!"
              << GetErrorMessage(result.status_code) << std::endl;
    return 0;
  }

  std::cout << "Run crypto client successfully!" << std::endl;

  absl::Notification finished;
  HpkeEncryptRequest hpke_encrypt_request;
  hpke_encrypt_request.mutable_public_key()->set_public_key(
      std::string(kPublicKey));
  hpke_encrypt_request.set_shared_info(std::string(kSharedInfo));
  hpke_encrypt_request.set_payload(std::string(kRequestPayload));
  hpke_encrypt_request.set_is_bidirectional(is_bidirectional);
  crypto_client->HpkeEncrypt(
      std::move(hpke_encrypt_request),
      absl::bind_front(HpkeEncryptCallback, is_bidirectional,
                       std::ref(finished)));
  finished.WaitForNotificationWithTimeout(absl::Seconds(3));

  result = crypto_client->Stop();
  if (!result.Successful()) {
    std::cout << "Cannot stop crypto client!"
              << GetErrorMessage(result.status_code) << std::endl;
  }

  result = Cpio::ShutdownCpio(cpio_options);
  if (!result.Successful()) {
    std::cout << "Failed to shutdown CPIO: "
              << GetErrorMessage(result.status_code) << std::endl;
  }

  return 0;
}
