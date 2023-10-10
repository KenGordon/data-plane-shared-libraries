/*
 * Copyright 2023 Google LLC
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

#ifndef ROMA_SANDBOX_WORKER_POOL_SRC_ERROR_CODES_H_
#define ROMA_SANDBOX_WORKER_POOL_SRC_ERROR_CODES_H_

#include "core/interface/errors.h"
#include "public/core/interface/execution_result.h"

namespace google::scp::core::errors {
REGISTER_COMPONENT_CODE(SC_ROMA_WORKER_POOL, 0x0CF0)
DEFINE_ERROR_CODE(SC_ROMA_WORKER_POOL_WORKER_INDEX_OUT_OF_BOUNDS,
                  SC_ROMA_WORKER_POOL, 0x0001,
                  "The worker index was out of bounds.",
                  HttpStatusCode::BAD_REQUEST)
}  // namespace google::scp::core::errors

#endif  // ROMA_SANDBOX_WORKER_POOL_SRC_ERROR_CODES_H_
