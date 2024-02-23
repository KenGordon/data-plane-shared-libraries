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

#include "src/core/interface/type_def.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::NotNull;
using ::testing::StrEq;

namespace google::scp::core::test {
namespace {

TEST(TypeDefTest, BytesBufferStringConstructor) {
  constexpr size_t str_len = 5;
  const std::string str = "12345";

  BytesBuffer buffer(str);

  EXPECT_EQ(buffer.capacity, str_len);
  EXPECT_EQ(buffer.length, str_len);

  ASSERT_THAT(buffer.bytes, NotNull());

  ASSERT_EQ(buffer.bytes->size(), str_len);
  EXPECT_THAT(std::string(buffer.bytes->begin(), buffer.bytes->end()),
              StrEq(str));
}

TEST(TypeDefTest, BytesBufferToString) {
  BytesBuffer buffer(10);
  for (Byte b : {'1', '2', '3', '4', '5'}) {
    buffer.bytes->emplace(buffer.bytes->begin() + buffer.length, b);
    buffer.length++;
  }

  EXPECT_THAT(buffer.ToString(), StrEq("12345"));

  // Changing the length causes us to see the other default inserted '\0'
  // after the emplaced string.
  buffer.length = buffer.capacity;
  auto actual_str = buffer.ToString();

  Byte arr[] = {'1', '2', '3', '4', '5', '\0', '\0', '\0', '\0', '\0'};
  std::string expected_str(arr, 10);
  EXPECT_THAT(actual_str, StrEq(expected_str));
}

}  // namespace
}  // namespace google::scp::core::test
