
#pragma once

#include "core/interface/errors.h"
#include "public/cpio/interface/error_codes.h"

namespace google::scp::core::errors {
REGISTER_COMPONENT_CODE(SC_AZURE_KMS_CLIENT_PROVIDER, 0x022B)

DEFINE_ERROR_CODE(SC_AZURE_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND,
                  SC_AZURE_KMS_CLIENT_PROVIDER, 0x0001,
                  "Cannot find cipher text",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

DEFINE_ERROR_CODE(SC_AZURE_KMS_CLIENT_PROVIDER_KEY_ID_NOT_FOUND,
                  SC_AZURE_KMS_CLIENT_PROVIDER, 0x0002,
                  "Cannot find decryption Key ID",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

DEFINE_ERROR_CODE(SC_AZURE_KMS_CLIENT_PROVIDER_BAD_UNWRAPPED_KEY,
                  SC_AZURE_KMS_CLIENT_PROVIDER, 0x0003,
                  "Unwrapped key is malformed.",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

MAP_TO_PUBLIC_ERROR_CODE(SC_AZURE_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND,
                         SC_CPIO_INVALID_REQUEST)

MAP_TO_PUBLIC_ERROR_CODE(SC_AZURE_KMS_CLIENT_PROVIDER_KEY_ID_NOT_FOUND,
                         SC_CPIO_INVALID_REQUEST)

MAP_TO_PUBLIC_ERROR_CODE(SC_AZURE_KMS_CLIENT_PROVIDER_BAD_UNWRAPPED_KEY,
                         SC_CPIO_INVALID_RESOURCE)

}  // namespace google::scp::core::errors