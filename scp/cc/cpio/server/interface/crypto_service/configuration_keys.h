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

#ifndef CPIO_SERVER_INTERFACE_CRYPTO_SERVICE_CONFIGURATION_KEYS_H_
#define CPIO_SERVER_INTERFACE_CRYPTO_SERVICE_CONFIGURATION_KEYS_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "public/cpio/proto/crypto_service/v1/crypto_service.pb.h"

namespace google::scp::cpio {
// Optional. All options are listed in kHpkeKemConfigMap. If not set, use the
// default value DHKEM_X25519_HKDF_SHA256.
static constexpr char kCryptoClientHpkeKem[] =
    "cmrt_sdk_crypto_client_hpke_kem";
// Optional. All options are listed in kHpkeKdfConfigMap. If not set, use the
// default value HKDF_SHA256.
static constexpr char kCryptoClientHpkeKdf[] =
    "cmrt_sdk_crypto_client_hpke_kdf";
// Optional. All options are listed in kHpkeAeadConfigMap. If not set, use the
// default value CHACHA20_POLY1305.
static constexpr char kCryptoClientHpkeAead[] =
    "cmrt_sdk_crypto_client_hpke_aead";
// Optional. If not set, use the default value 2. The number of
// CompletionQueues for the server.
// https://grpc.github.io/grpc/cpp/classgrpc_1_1_server_builder.html#aff66bd93cba7d4240a64550fe1fca88d
static constexpr char kCryptoClientCompletionQueueCount[] =
    "cmrt_sdk_crypto_client_completion_queue_count";
// Optional. If not set, use the default value 2. Minimum number of polling
// threads for the server.
// https://grpc.github.io/grpc/cpp/classgrpc_1_1_server_builder.html#aff66bd93cba7d4240a64550fe1fca88d
static constexpr char kCryptoClientMinPollers[] =
    "cmrt_sdk_crypto_client_min_pollers";
// Optional. If not set, use the default value 5. Maximum number of polling
// threads for the server.
// https://grpc.github.io/grpc/cpp/classgrpc_1_1_server_builder.html#aff66bd93cba7d4240a64550fe1fca88d
static constexpr char kCryptoClientMaxPollers[] =
    "cmrt_sdk_crypto_client_max_pollers";

// Static duration maps are heap allocated to avoid destructor call.
static const auto& kHpkeKemConfigMap =
    *new absl::flat_hash_map<std::string,
                             cmrt::sdk::crypto_service::v1::HpkeKem>{
        {"DHKEM_X25519_HKDF_SHA256",
         cmrt::sdk::crypto_service::v1::HpkeKem::DHKEM_X25519_HKDF_SHA256},
    };
static const auto& kHpkeKdfConfigMap =
    *new absl::flat_hash_map<std::string,
                             cmrt::sdk::crypto_service::v1::HpkeKdf>{
        {"HKDF_SHA256", cmrt::sdk::crypto_service::v1::HpkeKdf::HKDF_SHA256},
    };
static const auto& kHpkeAeadConfigMap =
    *new absl::flat_hash_map<std::string,
                             cmrt::sdk::crypto_service::v1::HpkeAead>{
        {"AES_128_GCM", cmrt::sdk::crypto_service::v1::HpkeAead::AES_128_GCM},
        {"AES_256_GCM", cmrt::sdk::crypto_service::v1::HpkeAead::AES_256_GCM},
        {"CHACHA20_POLY1305",
         cmrt::sdk::crypto_service::v1::HpkeAead::CHACHA20_POLY1305},
    };

}  // namespace google::scp::cpio

#endif  // CPIO_SERVER_INTERFACE_CRYPTO_SERVICE_CONFIGURATION_KEYS_H_
