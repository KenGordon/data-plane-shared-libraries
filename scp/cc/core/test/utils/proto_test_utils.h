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

#ifndef CORE_TEST_UTILS_PROTO_TEST_UTILS_H_
#define CORE_TEST_UTILS_PROTO_TEST_UTILS_H_

#include <gmock/gmock.h>

#include <string>

#include <google/protobuf/util/message_differencer.h>

namespace google::scp::core::test {
/// Matcher to compare protos.
MATCHER_P(EqualsProto, expected, "") {
  std::string explanation;
  protobuf::util::MessageDifferencer differ;
  differ.ReportDifferencesToString(&explanation);
  if (!differ.Compare(expected, arg)) {
    *result_listener << explanation;
    return false;
  }
  return true;
}

MATCHER(EqualsProto, "") {
  const auto& [actual, expected] = arg;
  return testing::ExplainMatchResult(EqualsProto(expected), actual,
                                     result_listener);
}
}  // namespace google::scp::core::test

#endif  // CORE_TEST_UTILS_PROTO_TEST_UTILS_H_
