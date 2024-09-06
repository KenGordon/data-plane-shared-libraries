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

#ifndef PUBLIC_CPIO_MOCK_PRIVATE_KEY_CLIENT_MOCK_PRIVATE_KEY_CLIENT_H_
#define PUBLIC_CPIO_MOCK_PRIVATE_KEY_CLIENT_MOCK_PRIVATE_KEY_CLIENT_H_

#include <gmock/gmock.h>

#include "absl/status/status.h"
#include "src/public/cpio/interface/private_key_client/private_key_client_interface.h"

namespace google::scp::cpio {
class MockPrivateKeyClient : public PrivateKeyClientInterface {
 public:
  MockPrivateKeyClient() {
    ON_CALL(*this, Init).WillByDefault(testing::Return(absl::OkStatus()));
    ON_CALL(*this, Run).WillByDefault(testing::Return(absl::OkStatus()));
    ON_CALL(*this, Stop).WillByDefault(testing::Return(absl::OkStatus()));
  }

  MOCK_METHOD(absl::Status, Init, (), (noexcept, override));
  MOCK_METHOD(absl::Status, Run, (), (noexcept, override));
  MOCK_METHOD(absl::Status, Stop, (), (noexcept, override));

  MOCK_METHOD(
      absl::Status, ListPrivateKeys,
      (cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest request,
       Callback<cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse>
           callback),
      (noexcept, override));
};

}  // namespace google::scp::cpio

#endif  // PUBLIC_CPIO_MOCK_PRIVATE_KEY_CLIENT_MOCK_PRIVATE_KEY_CLIENT_H_
