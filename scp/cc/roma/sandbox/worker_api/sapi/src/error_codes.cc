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

#include "scp/cc/roma/sandbox/worker_api/sapi/src/error_codes.h"

#include "absl/strings/str_cat.h"

absl::Status SapiStatusCodeToAbslStatus(int int_status_code) {
  SapiStatusCode status_code = static_cast<SapiStatusCode>(int_status_code);
  switch (status_code) {
    case SapiStatusCode::kOk:
      return absl::OkStatus();
    case SapiStatusCode::kUninitializedWorker:
      return absl::FailedPreconditionError(
          "A call to run code was issued with an uninitialized worker.");
    case SapiStatusCode::kCouldNotDeserializeInitData:
      return absl::InvalidArgumentError("Failed to deserialize init data.");
    case SapiStatusCode::kValidSandboxBufferRequired:
      return absl::InternalError(
          "Failed to create a valid sandbox2 buffer for sandbox "
          "communication.");
    case SapiStatusCode::kFailedToCreateBufferInsideSandboxee:
      return absl::InternalError(
          "Failed to create the Buffer from fd inside the sandboxee.");

      // No default. This will cause a compile error if a new enum value is
      // added without also updating this switch statement.
  }

  // It's technically valid C++ for an enum to take any int value.  That should
  // never happen, but handle it just in case.
  return absl::UnknownError(
      absl::StrCat("Unexpected value for SapiStatusCode: ", status_code));
}
