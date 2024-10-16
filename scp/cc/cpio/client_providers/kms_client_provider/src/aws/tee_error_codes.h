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

#ifndef CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_SRC_AWS_TEE_ERROR_CODES_H_
#define CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_SRC_AWS_TEE_ERROR_CODES_H_

#include "core/interface/errors.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/error_codes.h"

namespace google::scp::core::errors {
/// Registers component code as 0x0218 for AWS KMS client provider.
REGISTER_COMPONENT_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0218)

DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_ASSUME_ROLE_NOT_FOUND,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0001,
                  "No assume role found", HttpStatusCode::NOT_FOUND)

DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_CREDENTIAL_PROVIDER_NOT_FOUND,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0002,
                  "No credential provider found", HttpStatusCode::NOT_FOUND)

DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_REGION_NOT_FOUND,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0003, "No region found",
                  HttpStatusCode::NOT_FOUND)

// Deprecated.
DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0004,
                  "Cannot find the key arn", HttpStatusCode::BAD_REQUEST)

DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0005,
                  "Cannot find cipher text",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

// Deprecated.
DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0006, "Cannot decrpyt",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

DEFINE_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_KMSTOOL_CLI_EXECUTION_FAILED,
                  SC_TEE_AWS_KMS_CLIENT_PROVIDER, 0x0007,
                  "Cannot execute enclaves kmstools cli",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

MAP_TO_PUBLIC_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_ASSUME_ROLE_NOT_FOUND,
                         SC_CPIO_COMPONENT_FAILED_INITIALIZED)
MAP_TO_PUBLIC_ERROR_CODE(
    SC_TEE_AWS_KMS_CLIENT_PROVIDER_CREDENTIAL_PROVIDER_NOT_FOUND,
    SC_CPIO_COMPONENT_FAILED_INITIALIZED)
MAP_TO_PUBLIC_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_REGION_NOT_FOUND,
                         SC_CPIO_COMPONENT_FAILED_INITIALIZED)
MAP_TO_PUBLIC_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND,
                         SC_CPIO_INVALID_REQUEST)
MAP_TO_PUBLIC_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND,
                         SC_CPIO_INVALID_REQUEST)
MAP_TO_PUBLIC_ERROR_CODE(SC_TEE_AWS_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED,
                         SC_CPIO_INTERNAL_ERROR)
MAP_TO_PUBLIC_ERROR_CODE(
    SC_TEE_AWS_KMS_CLIENT_PROVIDER_KMSTOOL_CLI_EXECUTION_FAILED,
    SC_CPIO_INTERNAL_ERROR)

}  // namespace google::scp::core::errors

#endif  // CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_SRC_AWS_TEE_ERROR_CODES_H_
