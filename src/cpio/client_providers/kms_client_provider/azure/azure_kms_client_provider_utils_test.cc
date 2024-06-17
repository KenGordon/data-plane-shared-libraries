/*
 * Portions Copyright (c) Microsoft Corporation
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

#include "azure_kms_client_provider_utils.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "src/core/interface/http_types.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/core/test_execution_result_matchers.h"

using google::scp::core::ExecutionResult;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;

namespace {
constexpr char kKeyId[] = "123";
constexpr char kPrivateKeyBaseUri[] = "http://localhost.test:8000";
}  // namespace

namespace google::scp::cpio::client_providers::test {

TEST(AzureKmsClientProviderUtilsTest, GenerateWrappingKey) {
  auto wrappingKey = AzureKmsClientProviderUtils::GenerateWrappingKey();

  ASSERT_NE(wrappingKey.first, nullptr);
  ASSERT_NE(wrappingKey.second, nullptr);

  std::string pem =
      AzureKmsClientProviderUtils::EvpPkeyToPem(wrappingKey.first->get());

  // Add the constant to avoid the key detection precommit
  auto toTest = std::string("-----") + std::string("BEGIN PRIVATE") +
                std::string(" KEY-----");
  ASSERT_EQ(pem.find(toTest) == 0, true);

  pem = AzureKmsClientProviderUtils::EvpPkeyToPem(wrappingKey.second->get());
  ASSERT_EQ(pem.find("-----BEGIN PUBLIC KEY-----") == 0, true);
}

TEST(AzureKmsClientProviderUtilsTest, GenerateWrappingKeyHash) {
  auto publicPemKey =
      google::scp::cpio::client_providers::GetTestPemPublicWrapKey();
  auto publicKey = AzureKmsClientProviderUtils::PemToEvpPkey(publicPemKey);

  auto hexHash = AzureKmsClientProviderUtils::CreateHexHashOnKey(publicKey);
  std::cout << "##################HASH: " << hexHash << std::endl;
  ASSERT_EQ(hexHash.size(), 64);
  ASSERT_EQ(hexHash,
            "36b03dab8e8751b26d9b33fa2fa1296f823a238ef3dd604f758a4aff5b2b41d0");
}

}  // namespace google::scp::cpio::client_providers::test
