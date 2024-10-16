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

#include "public/cpio/adapters/private_key_client/src/private_key_client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/synchronization/notification.h"
#include "core/interface/errors.h"
#include "cpio/client_providers/private_key_client_provider/mock/mock_private_key_client_provider_with_overrides.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"
#include "public/cpio/adapters/private_key_client/mock/mock_private_key_client_with_overrides.h"
#include "public/cpio/interface/private_key_client/private_key_client_interface.h"
#include "public/cpio/interface/private_key_client/type_def.h"
#include "public/cpio/proto/private_key_service/v1/private_key_service.pb.h"

using google::cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest;
using google::cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::test::IsSuccessful;
using google::scp::core::test::ResultIs;
using google::scp::cpio::PrivateKeyClient;
using google::scp::cpio::PrivateKeyClientOptions;
using google::scp::cpio::mock::MockPrivateKeyClientWithOverrides;

namespace google::scp::cpio::test {
class PrivateKeyClientTest : public ::testing::Test {
 protected:
  PrivateKeyClientTest() {
    auto private_key_client_options =
        std::make_shared<PrivateKeyClientOptions>();
    client_ = std::make_unique<MockPrivateKeyClientWithOverrides>(
        private_key_client_options);

    EXPECT_THAT(client_->Init(), IsSuccessful());
    EXPECT_THAT(client_->Run(), IsSuccessful());
  }

  ~PrivateKeyClientTest() { EXPECT_THAT(client_->Stop(), IsSuccessful()); }

  std::unique_ptr<MockPrivateKeyClientWithOverrides> client_;
};

TEST_F(PrivateKeyClientTest, ListPrivateKeysSuccess) {
  EXPECT_CALL(*client_->GetPrivateKeyClientProvider(), ListPrivateKeys)
      .WillOnce([=](AsyncContext<ListPrivateKeysRequest,
                                 ListPrivateKeysResponse>& context) {
        context.response = std::make_shared<ListPrivateKeysResponse>();
        context.result = SuccessExecutionResult();
        context.Finish();
        return SuccessExecutionResult();
      });

  absl::Notification finished;
  EXPECT_THAT(client_->ListPrivateKeys(ListPrivateKeysRequest(),
                                       [&](const ExecutionResult result,
                                           ListPrivateKeysResponse response) {
                                         EXPECT_THAT(result, IsSuccessful());
                                         finished.Notify();
                                       }),
              IsSuccessful());
  finished.WaitForNotification();
}

TEST_F(PrivateKeyClientTest, ListPrivateKeysFailure) {
  EXPECT_CALL(*client_->GetPrivateKeyClientProvider(), ListPrivateKeys)
      .WillOnce([=](AsyncContext<ListPrivateKeysRequest,
                                 ListPrivateKeysResponse>& context) {
        context.result = FailureExecutionResult(SC_UNKNOWN);
        context.Finish();
        return FailureExecutionResult(SC_UNKNOWN);
      });

  absl::Notification finished;
  EXPECT_THAT(
      client_->ListPrivateKeys(
          ListPrivateKeysRequest(),
          [&](const ExecutionResult result, ListPrivateKeysResponse response) {
            EXPECT_THAT(result, ResultIs(FailureExecutionResult(SC_UNKNOWN)));
            finished.Notify();
          }),
      ResultIs(FailureExecutionResult(SC_UNKNOWN)));
  finished.WaitForNotification();
}

TEST_F(PrivateKeyClientTest, FailureToCreatePrivateKeyClientProvider) {
  auto failure = FailureExecutionResult(SC_UNKNOWN);
  client_->create_private_key_client_provider_result = failure;
  EXPECT_EQ(client_->Init(), failure);
}
}  // namespace google::scp::cpio::test
