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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_MOCK_MOCK_PRIVATE_KEY_FETCHER_PROVIDER_WITH_OVERRIDES_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_MOCK_MOCK_PRIVATE_KEY_FETCHER_PROVIDER_WITH_OVERRIDES_H_

#include <memory>
#include <string>

#include "scp/cc/core/interface/async_context.h"
#include "scp/cc/core/interface/http_client_interface.h"
#include "scp/cc/cpio/client_providers/private_key_fetcher_provider/src/private_key_fetcher_provider.h"
#include "scp/cc/public/core/interface/execution_result.h"

namespace google::scp::cpio::client_providers::mock {
class MockPrivateKeyFetcherProviderWithOverrides
    : public PrivateKeyFetcherProvider {
 public:
  MockPrivateKeyFetcherProviderWithOverrides(
      core::HttpClientInterface* http_client)
      : PrivateKeyFetcherProvider(http_client) {}

  core::ExecutionResult sign_http_request_result_mock =
      core::SuccessExecutionResult();
  std::shared_ptr<core::HttpRequest> signed_http_request_mock =
      std::make_shared<core::HttpRequest>();

 private:
  core::ExecutionResult SignHttpRequest(
      core::AsyncContext<PrivateKeyFetchingRequest, core::HttpRequest>&
          sign_http_request_context) noexcept override {
    sign_http_request_context.result = sign_http_request_result_mock;
    sign_http_request_context.response = signed_http_request_mock;
    sign_http_request_context.Finish();
    return sign_http_request_context.result;
  }
};
}  // namespace google::scp::cpio::client_providers::mock

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_MOCK_MOCK_PRIVATE_KEY_FETCHER_PROVIDER_WITH_OVERRIDES_H_
