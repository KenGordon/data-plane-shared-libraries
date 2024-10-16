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

#include "core/utils/src/base64.h"

#include <gtest/gtest.h>

#include <string>

#include "core/utils/src/error_codes.h"
#include "public/core/test/interface/execution_result_matchers.h"

using google::scp::core::test::IsSuccessfulAndHolds;
using google::scp::core::test::ResultIs;
using ::testing::StrEq;

namespace google::scp::core::utils::test {
TEST(Base64Test, Base64EncodeInvalidValue) {
  std::string empty;
  std::string encoded;
  EXPECT_THAT(
      Base64Encode(empty, encoded),
      ResultIs(FailureExecutionResult(errors::SC_CORE_UTILS_INVALID_INPUT)));
}

TEST(Base64Test, Base64EncodeValidValue) {
  std::string decoded("test_test_test");
  std::string encoded;
  ASSERT_SUCCESS(Base64Encode(decoded, encoded));
  EXPECT_THAT(encoded, StrEq("dGVzdF90ZXN0X3Rlc3Q="));
}

TEST(Base64Test, Base64DecodeInvalidValue) {
  // Not correctly padded - needs "==" appended.
  std::string encoded("sdasdasdas");
  std::string decoded;
  EXPECT_THAT(Base64Decode(encoded, decoded),
              ResultIs(FailureExecutionResult(
                  errors::SC_CORE_UTILS_INVALID_BASE64_ENCODING_LENGTH)));
}

TEST(Base64Test, Base64DecodeValidValues) {
  std::string empty;
  std::string decoded;
  ASSERT_SUCCESS(Base64Decode(empty, decoded));

  std::string encoded("dGVzdF90ZXN0X3Rlc3Q=");
  ASSERT_SUCCESS(Base64Decode(encoded, decoded));
  EXPECT_THAT(decoded, StrEq("test_test_test"));
}

TEST(Base64Test, PadBase64EncodingTest) {
  EXPECT_THAT(PadBase64Encoding("1234"), IsSuccessfulAndHolds("1234"));

  // This scenario should never happen in reality but will return error.
  EXPECT_THAT(PadBase64Encoding("12345"),
              ResultIs(FailureExecutionResult(
                  errors::SC_CORE_UTILS_INVALID_BASE64_ENCODING_LENGTH)));

  EXPECT_THAT(PadBase64Encoding("123456"), IsSuccessfulAndHolds("123456=="));

  EXPECT_THAT(PadBase64Encoding("1234567"), IsSuccessfulAndHolds("1234567="));
}

}  // namespace google::scp::core::utils::test
