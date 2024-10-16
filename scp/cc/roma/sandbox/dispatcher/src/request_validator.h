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

#ifndef ROMA_SANDBOX_DISPATCHER_SRC_REQUEST_VALIDATOR_H_
#define ROMA_SANDBOX_DISPATCHER_SRC_REQUEST_VALIDATOR_H_

#include <memory>

#include "public/core/interface/execution_result.h"
#include "roma/interface/roma.h"
#include "roma/sandbox/constants/constants.h"
#include "roma/sandbox/worker_api/src/worker_api.h"

namespace google::scp::roma::sandbox::dispatcher::request_validator {
template <typename T>
struct RequestValidator {};

/**
 * @brief Template specialization to validate a CodeObject.
 */
template <>
struct RequestValidator<CodeObject> {
  static core::ExecutionResult Validate(const CodeObject& request) {
    if (request.js.empty() && request.wasm.empty()) {
      return core::FailureExecutionResult(SC_UNKNOWN);
    }

    if (!request.js.empty() && !request.wasm.empty()) {
      return core::FailureExecutionResult(SC_UNKNOWN);
    }

    if (request.version_string.empty() || request.id.empty()) {
      return core::FailureExecutionResult(SC_UNKNOWN);
    }

    return core::SuccessExecutionResult();
  }
};

/**
 * @brief Common validation fields for invocation requests.
 */
template <typename RequestT>
static core::ExecutionResult InvocationRequestCommon(const RequestT& request) {
  if (request.handler_name.empty() || request.version_string.empty() ||
      request.id.empty()) {
    return core::FailureExecutionResult(SC_UNKNOWN);
  }

  if (request.treat_input_as_byte_str && request.input.size() > 1) {
    return core::FailureExecutionResult(
        core::errors::
            SC_ROMA_DISPATCHER_DISPATCH_DISALLOWED_MULTIPLE_BYTE_STR_INPUTS);
  }

  return core::SuccessExecutionResult();
}

/**
 * @brief Template specialization to validate a InvocationStrRequest.
 */
template <typename TMetadata>
struct RequestValidator<InvocationStrRequest<TMetadata>> {
  static core::ExecutionResult Validate(
      const InvocationStrRequest<TMetadata>& request) {
    return InvocationRequestCommon(request);
  }
};

/**
 * @brief Template specialization to validate a InvocationSharedRequest.
 */
template <typename TMetadata>
struct RequestValidator<InvocationSharedRequest<TMetadata>> {
  static core::ExecutionResult Validate(
      const InvocationSharedRequest<TMetadata>& request) {
    return InvocationRequestCommon(request);
  }
};

/**
 * @brief Template specialization to validate a InvocationStrViewRequest.
 */
template <typename TMetadata>
struct RequestValidator<InvocationStrViewRequest<TMetadata>> {
  static core::ExecutionResult Validate(
      const InvocationStrViewRequest<TMetadata>& request) {
    return InvocationRequestCommon(request);
  }
};
}  // namespace google::scp::roma::sandbox::dispatcher::request_validator

#endif  // ROMA_SANDBOX_DISPATCHER_SRC_REQUEST_VALIDATOR_H_
