// Copyright 2022 Google LLC
// Copyright (C) Microsoft Corporation. All rights reserved.
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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AZURE_ERROR_CODES_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AZURE_ERROR_CODES_H_

#include "core/interface/errors.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/error_codes.h"

namespace google::scp::core::errors {

REGISTER_COMPONENT_CODE(SC_AZURE_PRIVATE_KEY_FETCHER_PROVIDER, 0x022B)

DEFINE_ERROR_CODE(
    SC_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND,
    SC_AZURE_PRIVATE_KEY_FETCHER_PROVIDER, 0x0001,
    "No credentials provider found", HttpStatusCode::NOT_FOUND)

MAP_TO_PUBLIC_ERROR_CODE(
    SC_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND,
    SC_CPIO_COMPONENT_FAILED_INITIALIZED)
}  // namespace google::scp::core::errors

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AZURE_ERROR_CODES_H_
