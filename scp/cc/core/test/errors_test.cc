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

#include "core/interface/errors.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "core/common/concurrent_queue/src/concurrent_queue.h"

using ::testing::StrEq;

namespace google::scp::core::errors::test {
TEST(ERRORS, ComponentCodeRegistered) {
  REGISTER_COMPONENT_CODE(COMPONENT_NAME, 0x7FFF)

  EXPECT_TRUE(COMPONENT_NAME && COMPONENT_NAME == 0x7FFF);
  EXPECT_TRUE(registered_0x7FFF);
}

TEST(ERRORS, ErrorCodeDefined) {
  REGISTER_COMPONENT_CODE(COMPONENT_NAME, 0x7FFF)

  DEFINE_ERROR_CODE(COMPONENT_NAME_ERROR, COMPONENT_NAME, 0x0001,
                    "Component error message test", HttpStatusCode::BAD_REQUEST)

  EXPECT_TRUE(initialized_COMPONENT_NAME0x0001);
}

TEST(ERRORS, ErrorMessageReturn) {
  REGISTER_COMPONENT_CODE(COMPONENT_NAME, 0x7FFF)

  DEFINE_ERROR_CODE(COMPONENT_NAME_ERROR, COMPONENT_NAME, 0xFFFF,
                    "Component error message test", HttpStatusCode::BAD_REQUEST)

  EXPECT_THAT(GetErrorMessage(COMPONENT_NAME_ERROR),
              StrEq("Component error message test"));
}

TEST(ERRORS, ErrorMessageSuccessErrorCode) {
  EXPECT_STREQ(GetErrorMessage(SC_OK).data(), "Success");
}

TEST(ERRORS, ErrorMessageUnknownErrorCode) {
  EXPECT_STREQ(GetErrorMessage(SC_UNKNOWN).data(), "Unknown Error");
}

TEST(ERRORS, ErrorMessageUndefinedErrorCode) {
  EXPECT_STREQ(GetErrorMessage(UINT64_MAX).data(), "InvalidErrorCode");
}

TEST(ERRORS, MapErrorCodePublic) {
  REGISTER_COMPONENT_CODE(PUBLIC_COMPONENT_NAME, 0x7EFF)

  DEFINE_ERROR_CODE(PUBLIC_COMPONENT_ERROR, PUBLIC_COMPONENT_NAME, 0xFFFF,
                    "Public error message test", HttpStatusCode::BAD_REQUEST)
  REGISTER_COMPONENT_CODE(COMPONENT_NAME, 0x7DFF)
  DEFINE_ERROR_CODE(COMPONENT_NAME_ERROR, COMPONENT_NAME, 0xFFFF,
                    "Component error message test", HttpStatusCode::BAD_REQUEST)
  MAP_TO_PUBLIC_ERROR_CODE(COMPONENT_NAME_ERROR, PUBLIC_COMPONENT_ERROR);
  EXPECT_STREQ(GetErrorMessage(GetPublicErrorCode(COMPONENT_NAME_ERROR)).data(),
               "Public error message test");
}

TEST(ERRORS, NoAssociatedPublicErrorCode) {
  REGISTER_COMPONENT_CODE(COMPONENT_NAME, 0x7DFF)
  DEFINE_ERROR_CODE(COMPONENT_NAME_ERROR, COMPONENT_NAME, 0xEFFF,
                    "Component error message test", HttpStatusCode::BAD_REQUEST)
  EXPECT_EQ(GetPublicErrorCode(COMPONENT_NAME_ERROR), SC_UNKNOWN);
}

}  // namespace google::scp::core::errors::test
