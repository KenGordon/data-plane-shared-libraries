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

#include "cpio/client_providers/kms_client_provider/src/aws/tee_aws_kms_client_provider_utils.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <string>
#include <thread>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"

using ::testing::IsEmpty;
using ::testing::StrEq;

namespace google::scp::cpio::client_providers::utils {

TEST(TeeAwsKmsClientProviderUtilsTest, ExecOutputsEmptyString) {
  const absl::StatusOr<std::string> output =
      Exec({"./scp/cc/cpio/client_providers/kms_client_provider/test/aws/true",
            nullptr});
  ASSERT_TRUE(output.ok());
  EXPECT_THAT(*output, IsEmpty());
}

TEST(TeeAwsKmsClientProviderUtilsTest, ExecSingleThreadedHelloWorld) {
  const absl::StatusOr<std::string> output =
      Exec({"./scp/cc/cpio/client_providers/kms_client_provider/test/aws/hello",
            nullptr});
  ASSERT_TRUE(output.ok());
  EXPECT_THAT(*output, StrEq("Hello, world!\n"));
}

TEST(TeeAwsKmsClientProviderUtilsTest, ExecMultiThreadedHelloWorld) {
  constexpr int kNumThreads = 50;
  std::array<absl::StatusOr<std::string>, kNumThreads> outputs;
  std::vector<std::thread> exec_threads;
  exec_threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    exec_threads.emplace_back([&, i] {
      outputs[i] = Exec(
          {"./scp/cc/cpio/client_providers/kms_client_provider/test/aws/hello",
           absl::StrCat("--name=", i).data(), nullptr});
    });
  }
  for (int i = 0; i < kNumThreads; ++i) {
    exec_threads[i].join();
    ASSERT_TRUE(outputs[i].ok());
    EXPECT_THAT(*outputs[i], StrEq(absl::Substitute("Hello, $0!\n", i)));
  }
}

TEST(TeeAwsKmsClientProviderUtilsTest, ExecChildProcessFails) {
  EXPECT_FALSE(
      Exec({"./scp/cc/cpio/client_providers/kms_client_provider/test/aws/false",
            nullptr})
          .ok());
}

TEST(TeeAwsKmsClientProviderUtilsTest, ExecFailsWhenCantFindBinary) {
  EXPECT_EQ(Exec({"/does-not-exist", nullptr}).status().code(),
            absl::StatusCode::kNotFound);
}

}  // namespace google::scp::cpio::client_providers::utils
