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

#ifndef CORE_CREDENTIALS_PROVIDER_SRC_ERROR_CODES_H_
#define CORE_CREDENTIALS_PROVIDER_SRC_ERROR_CODES_H_

#include "public/core/interface/execution_result.h"
#include "scp/cc/core/interface/errors.h"

namespace google::scp::core::errors {

REGISTER_COMPONENT_CODE(SC_CREDENTIALS_PROVIDER, 0x000F)

DEFINE_ERROR_CODE(SC_CREDENTIALS_PROVIDER_FAILED_TO_FETCH_CREDENTIALS,
                  SC_CREDENTIALS_PROVIDER, 0x0001,
                  "Fetching the credential failed.",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

DEFINE_ERROR_CODE(SC_CREDENTIALS_PROVIDER_INITIALIZATION_FAILED,
                  SC_CREDENTIALS_PROVIDER, 0x0002,
                  "Cannot initialize the credential provider.",
                  HttpStatusCode::INTERNAL_SERVER_ERROR)

}  // namespace google::scp::core::errors

#endif  // CORE_CREDENTIALS_PROVIDER_SRC_ERROR_CODES_H_
