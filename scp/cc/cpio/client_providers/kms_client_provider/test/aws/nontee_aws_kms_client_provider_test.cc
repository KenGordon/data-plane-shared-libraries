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

#include "cpio/client_providers/kms_client_provider/src/aws/nontee_aws_kms_client_provider.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/KMSErrors.h>

#include "absl/synchronization/notification.h"
#include "core/async_executor/mock/mock_async_executor.h"
#include "core/interface/async_context.h"
#include "core/utils/src/base64.h"
#include "cpio/client_providers/kms_client_provider/mock/aws/mock_nontee_aws_kms_client_provider_with_overrides.h"
#include "cpio/client_providers/kms_client_provider/src/aws/nontee_error_codes.h"
#include "cpio/client_providers/role_credentials_provider/mock/mock_role_credentials_provider.h"
#include "cpio/common/src/aws/error_codes.h"
#include "public/core/interface/execution_result.h"
#include "public/core/test/interface/execution_result_matchers.h"

using Aws::InitAPI;
using Aws::SDKOptions;
using Aws::ShutdownAPI;
using Aws::Client::AWSError;
using Aws::KMS::KMSClient;
using Aws::KMS::KMSErrors;
using Aws::KMS::Model::DecryptOutcome;
using AwsDecryptRequest = Aws::KMS::Model::DecryptRequest;
using Aws::KMS::Model::DecryptResult;
using Aws::Utils::ByteBuffer;
using crypto::tink::Aead;
using google::cmrt::sdk::kms_service::v1::DecryptRequest;
using google::cmrt::sdk::kms_service::v1::DecryptResponse;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::ExecutionStatus;
using google::scp::core::FailureExecutionResult;
using google::scp::core::async_executor::mock::MockAsyncExecutor;
using google::scp::core::test::ResultIs;
using google::scp::core::utils::Base64Decode;
using ::testing::StrEq;

using google::scp::core::errors::
    SC_AWS_KMS_CLIENT_PROVIDER_ASSUME_ROLE_NOT_FOUND;
using google::scp::core::errors::
    SC_AWS_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND;
using google::scp::core::errors::
    SC_AWS_KMS_CLIENT_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND;
using google::scp::core::errors::SC_AWS_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED;
using google::scp::core::errors::SC_AWS_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND;
using google::scp::core::errors::SC_AWS_KMS_CLIENT_PROVIDER_REGION_NOT_FOUND;
using google::scp::cpio::client_providers::mock::MockKMSClient;
using google::scp::cpio::client_providers::mock::
    MockNonteeAwsKmsClientProviderWithOverrides;
using google::scp::cpio::client_providers::mock::MockRoleCredentialsProvider;

static constexpr char kAssumeRoleArn[] = "assumeRoleArn";
static constexpr char kKeyArn[] = "keyArn";
static constexpr char kWrongKeyArn[] = "wrongkeyArn";
static constexpr char kCiphertext[] = "ciphertext";
static constexpr char kPlaintext[] = "plaintext";
static constexpr char kRegion[] = "us-east-1";

namespace google::scp::cpio::client_providers::test {
class TeeAwsKmsClientProviderTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    SDKOptions options;
    InitAPI(options);
  }

  static void TearDownTestSuite() {
    SDKOptions options;
    ShutdownAPI(options);
  }

  void SetUp() override {
    mock_kms_client_ = std::make_shared<MockKMSClient>();

    // Mocks DecryptRequest.
    AwsDecryptRequest decrypt_request;
    decrypt_request.SetKeyId(kKeyArn);
    std::string ciphertext = std::string(kCiphertext);
    std::string decoded_ciphertext;
    Base64Decode(ciphertext, decoded_ciphertext);
    ByteBuffer ciphertext_buffer(
        reinterpret_cast<const unsigned char*>(decoded_ciphertext.data()),
        decoded_ciphertext.length());
    decrypt_request.SetCiphertextBlob(ciphertext_buffer);
    mock_kms_client_->decrypt_request_mock = decrypt_request;

    // Mocks success DecryptRequestOutcome.
    DecryptResult decrypt_result;
    decrypt_result.SetKeyId(kKeyArn);
    std::string plaintext = std::string(kPlaintext);
    ByteBuffer plaintext_buffer(
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.length());
    decrypt_result.SetPlaintext(plaintext_buffer);
    DecryptOutcome decrypt_outcome(decrypt_result);
    mock_kms_client_->decrypt_outcome_mock = decrypt_outcome;

    mock_credentials_provider_ =
        std::make_shared<MockRoleCredentialsProvider>();
    client_ = std::make_unique<MockNonteeAwsKmsClientProviderWithOverrides>(
        mock_credentials_provider_, mock_kms_client_, mock_io_async_executor_);
  }

  void TearDown() override { EXPECT_SUCCESS(client_->Stop()); }

  std::unique_ptr<MockNonteeAwsKmsClientProviderWithOverrides> client_;
  std::shared_ptr<MockKMSClient> mock_kms_client_;
  std::shared_ptr<MockAsyncExecutor> mock_io_async_executor_ =
      std::make_shared<MockAsyncExecutor>();
  std::shared_ptr<RoleCredentialsProviderInterface> mock_credentials_provider_;
};

TEST_F(TeeAwsKmsClientProviderTest, MissingCredentialsProvider) {
  client_ = std::make_unique<MockNonteeAwsKmsClientProviderWithOverrides>(
      nullptr, mock_kms_client_, mock_io_async_executor_);

  EXPECT_THAT(client_->Init(),
              ResultIs(FailureExecutionResult(
                  SC_AWS_KMS_CLIENT_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND)));
}

TEST_F(TeeAwsKmsClientProviderTest, MissingAssumeRoleArn) {
  EXPECT_SUCCESS(client_->Init());
  EXPECT_SUCCESS(client_->Run());

  auto kms_decrypt_request = std::make_shared<DecryptRequest>();
  kms_decrypt_request->set_kms_region(kRegion);
  kms_decrypt_request->set_key_resource_name(kKeyArn);
  kms_decrypt_request->set_ciphertext(kCiphertext);

  AsyncContext<DecryptRequest, DecryptResponse> context(
      kms_decrypt_request,
      [&](AsyncContext<DecryptRequest, DecryptResponse>& context) {});

  EXPECT_THAT(client_->Decrypt(context),
              ResultIs(FailureExecutionResult(
                  SC_AWS_KMS_CLIENT_PROVIDER_ASSUME_ROLE_NOT_FOUND)));
}

TEST_F(TeeAwsKmsClientProviderTest, MissingRegion) {
  EXPECT_SUCCESS(client_->Init());
  EXPECT_SUCCESS(client_->Run());

  auto kms_decrypt_request = std::make_shared<DecryptRequest>();
  kms_decrypt_request->set_account_identity(kAssumeRoleArn);
  kms_decrypt_request->set_key_resource_name(kKeyArn);
  kms_decrypt_request->set_ciphertext(kCiphertext);

  AsyncContext<DecryptRequest, DecryptResponse> context(
      kms_decrypt_request,
      [&](AsyncContext<DecryptRequest, DecryptResponse>& context) {});

  EXPECT_THAT(client_->Decrypt(context),
              ResultIs(FailureExecutionResult(
                  SC_AWS_KMS_CLIENT_PROVIDER_REGION_NOT_FOUND)));
}

TEST_F(TeeAwsKmsClientProviderTest, SuccessToDecrypt) {
  EXPECT_SUCCESS(client_->Init());
  EXPECT_SUCCESS(client_->Run());

  auto kms_decrypt_request = std::make_shared<DecryptRequest>();
  kms_decrypt_request->set_kms_region(kRegion);
  kms_decrypt_request->set_account_identity(kAssumeRoleArn);
  kms_decrypt_request->set_key_resource_name(kKeyArn);
  kms_decrypt_request->set_ciphertext(kCiphertext);
  absl::Notification condition;

  AsyncContext<DecryptRequest, DecryptResponse> context(
      kms_decrypt_request,
      [&](AsyncContext<DecryptRequest, DecryptResponse>& context) {
        EXPECT_SUCCESS(context.result);
        EXPECT_THAT(context.response->plaintext(), StrEq(kPlaintext));
        condition.Notify();
      });

  EXPECT_SUCCESS(client_->Decrypt(context));
  condition.WaitForNotification();
}

TEST_F(TeeAwsKmsClientProviderTest, MissingCipherText) {
  EXPECT_SUCCESS(client_->Init());
  EXPECT_SUCCESS(client_->Run());

  auto kms_decrypt_request = std::make_shared<DecryptRequest>();
  kms_decrypt_request->set_kms_region(kRegion);
  kms_decrypt_request->set_account_identity(kAssumeRoleArn);
  kms_decrypt_request->set_key_resource_name(kKeyArn);
  absl::Notification condition;

  AsyncContext<DecryptRequest, DecryptResponse> context(
      kms_decrypt_request,
      [&](AsyncContext<DecryptRequest, DecryptResponse>& context) {
        EXPECT_THAT(context.result,
                    ResultIs(FailureExecutionResult(
                        SC_AWS_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND)));
        condition.Notify();
      });
  EXPECT_THAT(client_->Decrypt(context),
              ResultIs(FailureExecutionResult(
                  SC_AWS_KMS_CLIENT_PROVIDER_CIPHER_TEXT_NOT_FOUND)));
  condition.WaitForNotification();
}

TEST_F(TeeAwsKmsClientProviderTest, MissingKeyArn) {
  EXPECT_SUCCESS(client_->Init());
  EXPECT_SUCCESS(client_->Run());

  auto kms_decrypt_request = std::make_shared<DecryptRequest>();
  kms_decrypt_request->set_kms_region(kRegion);
  kms_decrypt_request->set_account_identity(kAssumeRoleArn);
  kms_decrypt_request->set_ciphertext(kCiphertext);
  absl::Notification condition;

  AsyncContext<DecryptRequest, DecryptResponse> context(
      kms_decrypt_request,
      [&](AsyncContext<DecryptRequest, DecryptResponse>& context) {
        condition.Notify();
        EXPECT_THAT(context.result,
                    ResultIs(FailureExecutionResult(
                        SC_AWS_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND)));
      });
  EXPECT_THAT(client_->Decrypt(context),
              ResultIs(FailureExecutionResult(
                  SC_AWS_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND)));
  condition.WaitForNotification();
}

TEST_F(TeeAwsKmsClientProviderTest, FailedDecryption) {
  EXPECT_SUCCESS(client_->Init());
  EXPECT_SUCCESS(client_->Run());

  auto kms_decrypt_request = std::make_shared<DecryptRequest>();
  kms_decrypt_request->set_kms_region(kRegion);
  kms_decrypt_request->set_account_identity(kAssumeRoleArn);
  kms_decrypt_request->set_key_resource_name(kWrongKeyArn);
  kms_decrypt_request->set_ciphertext(kCiphertext);
  absl::Notification condition;

  AsyncContext<DecryptRequest, DecryptResponse> context(
      kms_decrypt_request,
      [&](AsyncContext<DecryptRequest, DecryptResponse>& context) {
        condition.Notify();
        EXPECT_THAT(context.result,
                    ResultIs(FailureExecutionResult(
                        SC_AWS_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED)));
      });
  EXPECT_SUCCESS(client_->Decrypt(context));
  condition.WaitForNotification();
}
}  // namespace google::scp::cpio::client_providers::test
