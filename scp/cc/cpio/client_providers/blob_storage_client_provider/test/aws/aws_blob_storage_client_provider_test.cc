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

#include "cpio/client_providers/blob_storage_client_provider/src/aws/aws_blob_storage_client_provider.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <aws/s3/S3Client.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/Object.h>
#include <aws/s3/model/PutObjectRequest.h>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "core/async_executor/mock/mock_async_executor.h"
#include "cpio/client_providers/blob_storage_client_provider/test/aws/mock_s3_client.h"
#include "cpio/client_providers/instance_client_provider/mock/mock_instance_client_provider.h"
#include "cpio/common/src/aws/error_codes.h"
#include "public/core/test/interface/execution_result_matchers.h"

using Aws::InitAPI;
using Aws::SDKOptions;
using Aws::ShutdownAPI;
using Aws::StringStream;
using Aws::Vector;
using Aws::Client::AWSError;
using Aws::Client::ClientConfiguration;
using Aws::S3::S3Errors;
using Aws::S3::Model::DeleteObjectOutcome;
using Aws::S3::Model::DeleteObjectRequest;
using Aws::S3::Model::DeleteObjectResult;
using Aws::S3::Model::GetObjectOutcome;
using Aws::S3::Model::GetObjectRequest;
using Aws::S3::Model::GetObjectResult;
using Aws::S3::Model::ListObjectsOutcome;
using Aws::S3::Model::ListObjectsRequest;
using Aws::S3::Model::ListObjectsResult;
using Aws::S3::Model::Object;
using Aws::S3::Model::PutObjectOutcome;
using Aws::S3::Model::PutObjectRequest;
using Aws::S3::Model::PutObjectResult;
using google::cmrt::sdk::blob_storage_service::v1::Blob;
using google::cmrt::sdk::blob_storage_service::v1::BlobMetadata;
using google::cmrt::sdk::blob_storage_service::v1::DeleteBlobRequest;
using google::cmrt::sdk::blob_storage_service::v1::DeleteBlobResponse;
using google::cmrt::sdk::blob_storage_service::v1::GetBlobRequest;
using google::cmrt::sdk::blob_storage_service::v1::GetBlobResponse;
using google::cmrt::sdk::blob_storage_service::v1::ListBlobsMetadataRequest;
using google::cmrt::sdk::blob_storage_service::v1::ListBlobsMetadataResponse;
using google::cmrt::sdk::blob_storage_service::v1::PutBlobRequest;
using google::cmrt::sdk::blob_storage_service::v1::PutBlobResponse;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::async_executor::mock::MockAsyncExecutor;
using google::scp::core::errors::SC_AWS_INTERNAL_SERVICE_ERROR;
using google::scp::core::test::IsSuccessful;
using google::scp::core::test::ResultIs;
using google::scp::cpio::client_providers::mock::MockInstanceClientProvider;
using google::scp::cpio::client_providers::mock::MockS3Client;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::ExplainMatchResult;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrEq;

namespace {
constexpr char kResourceNameMock[] =
    "arn:aws:ec2:us-east-1:123456789012:instance/i-0e9801d129EXAMPLE";
}

namespace google::scp::cpio::client_providers {

class MockAwsS3Factory : public AwsS3Factory {
 public:
  MOCK_METHOD(core::ExecutionResultOr<std::shared_ptr<Aws::S3::S3Client>>,
              CreateClient,
              (ClientConfiguration&,
               const std::shared_ptr<core::AsyncExecutorInterface>&),
              (noexcept, override));
};

class AwsBlobStorageClientProviderTest : public ::testing::Test {
 protected:
  AwsBlobStorageClientProviderTest()
      : instance_client_(std::make_shared<MockInstanceClientProvider>()),
        s3_factory_(std::make_shared<NiceMock<MockAwsS3Factory>>()),
        provider_(std::make_shared<BlobStorageClientOptions>(),
                  instance_client_, std::make_shared<MockAsyncExecutor>(),
                  std::make_shared<MockAsyncExecutor>(), s3_factory_) {
    InitAPI(options_);
    instance_client_->instance_resource_name = kResourceNameMock;
    s3_client_ = std::make_shared<NiceMock<MockS3Client>>();

    ON_CALL(*s3_factory_, CreateClient).WillByDefault(Return(s3_client_));

    get_blob_context_.request = std::make_shared<GetBlobRequest>();
    get_blob_context_.callback = [this](auto) {
      absl::MutexLock l(&finish_called_mu_);
      finish_called_ = true;
    };

    list_blobs_metadata_context_.request =
        std::make_shared<ListBlobsMetadataRequest>();
    list_blobs_metadata_context_.callback = [this](auto) {
      absl::MutexLock l(&finish_called_mu_);
      finish_called_ = true;
    };

    put_blob_context_.request = std::make_shared<PutBlobRequest>();
    put_blob_context_.callback = [this](auto) {
      absl::MutexLock l(&finish_called_mu_);
      finish_called_ = true;
    };

    delete_blob_context_.request = std::make_shared<DeleteBlobRequest>();
    delete_blob_context_.callback = [this](auto) {
      absl::MutexLock l(&finish_called_mu_);
      finish_called_ = true;
    };

    EXPECT_SUCCESS(provider_.Init());
    EXPECT_SUCCESS(provider_.Run());
  }

  ~AwsBlobStorageClientProviderTest() { ShutdownAPI(options_); }

  std::shared_ptr<MockInstanceClientProvider> instance_client_;
  std::shared_ptr<MockS3Client> s3_client_;
  std::shared_ptr<MockAwsS3Factory> s3_factory_;
  AwsBlobStorageClientProvider provider_;

  AsyncContext<GetBlobRequest, GetBlobResponse> get_blob_context_;

  AsyncContext<ListBlobsMetadataRequest, ListBlobsMetadataResponse>
      list_blobs_metadata_context_;

  AsyncContext<PutBlobRequest, PutBlobResponse> put_blob_context_;

  AsyncContext<DeleteBlobRequest, DeleteBlobResponse> delete_blob_context_;
  // We check that this gets flipped after every call to ensure the context's
  // Finish() is called.
  absl::Mutex finish_called_mu_;
  bool finish_called_ ABSL_GUARDED_BY(finish_called_mu_) = false;

  SDKOptions options_;
};

MATCHER_P2(HasBucketAndKey, bucket, key, "") {
  return ExplainMatchResult(Eq(bucket), arg.GetBucket(), result_listener) &&
         ExplainMatchResult(Eq(key), arg.GetKey(), result_listener);
}

TEST_F(AwsBlobStorageClientProviderTest,
       RunWithCreateClientConfigurationFailed) {
  ExecutionResult failure_result = FailureExecutionResult(SC_UNKNOWN);
  instance_client_->get_instance_resource_name_mock = failure_result;

  EXPECT_SUCCESS(provider_.Init());
  EXPECT_THAT(provider_.Run(), ResultIs(failure_result));
}

TEST_F(AwsBlobStorageClientProviderTest, GetBlobFailure) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";
  get_blob_context_.request->mutable_blob_metadata()->set_bucket_name(
      bucket_name);
  get_blob_context_.request->mutable_blob_metadata()->set_blob_name(blob_name);
  get_blob_context_.callback =
      [this](AsyncContext<GetBlobRequest, GetBlobResponse>& get_blob_context) {
        EXPECT_THAT(
            get_blob_context.result,
            ResultIs(FailureExecutionResult(SC_AWS_INTERNAL_SERVICE_ERROR)));
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(*s3_client_,
              GetObjectAsync(HasBucketAndKey(bucket_name, blob_name), _, _))
      .WillOnce([](auto, auto callback, auto) {
        GetObjectRequest get_object_request;
        AWSError<S3Errors> s3_error(S3Errors::ACCESS_DENIED, false);
        GetObjectOutcome get_object_outcome(s3_error);
        callback(nullptr /*s3_client*/, get_object_request,
                 std::move(get_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.GetBlob(get_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

TEST_F(AwsBlobStorageClientProviderTest, GetBlobSuccess) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";
  std::string blob_data("Hello world!");
  get_blob_context_.request->mutable_blob_metadata()->set_bucket_name(
      bucket_name);
  get_blob_context_.request->mutable_blob_metadata()->set_blob_name(blob_name);
  get_blob_context_.callback =
      [this, &bucket_name, &blob_name, &blob_data](
          AsyncContext<GetBlobRequest, GetBlobResponse>& get_blob_context) {
        ASSERT_SUCCESS(get_blob_context.result);
        EXPECT_THAT(get_blob_context.response->blob().metadata().bucket_name(),
                    StrEq(bucket_name));
        EXPECT_THAT(get_blob_context.response->blob().metadata().blob_name(),
                    StrEq(blob_name));
        EXPECT_THAT(get_blob_context.response->blob().data(), StrEq(blob_data));

        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(*s3_client_,
              GetObjectAsync(HasBucketAndKey(bucket_name, blob_name), _, _))
      .WillOnce([&blob_data](auto, auto callback, auto) {
        GetObjectRequest get_object_request;
        GetObjectResult get_object_result;
        StringStream* input_data = new StringStream("");
        *input_data << blob_data;

        get_object_result.ReplaceBody(input_data);
        get_object_result.SetContentLength(12);
        GetObjectOutcome get_object_outcome(std::move(get_object_result));
        callback(nullptr /*s3_client*/, get_object_request,
                 std::move(get_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.GetBlob(get_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

MATCHER_P3(HasBucketKeyAndRange, bucket, key, range, "") {
  return ExplainMatchResult(HasBucketAndKey(bucket, key), arg,
                            result_listener) &&
         ExplainMatchResult(Eq(range), arg.GetRange(), result_listener);
}

TEST_F(AwsBlobStorageClientProviderTest, GetBlobWithByteRange) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";
  std::string blob_data("Hello world!");
  get_blob_context_.request->mutable_blob_metadata()->set_bucket_name(
      bucket_name);
  get_blob_context_.request->mutable_blob_metadata()->set_blob_name(blob_name);
  get_blob_context_.request->mutable_byte_range()->set_begin_byte_index(5);
  get_blob_context_.request->mutable_byte_range()->set_end_byte_index(100);
  get_blob_context_.callback =
      [this, &bucket_name, &blob_name, &blob_data](
          AsyncContext<GetBlobRequest, GetBlobResponse>& get_blob_context) {
        ASSERT_SUCCESS(get_blob_context.result);
        EXPECT_THAT(get_blob_context.response->blob().metadata().bucket_name(),
                    StrEq(bucket_name));
        EXPECT_THAT(get_blob_context.response->blob().metadata().blob_name(),
                    StrEq(blob_name));
        EXPECT_THAT(get_blob_context.response->blob().data(), StrEq(blob_data));

        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(
      *s3_client_,
      GetObjectAsync(
          HasBucketKeyAndRange(bucket_name, blob_name, "bytes=5-100"), _, _))
      .WillOnce([&blob_data](auto, auto callback, auto) {
        GetObjectRequest get_object_request;
        GetObjectResult get_object_result;
        StringStream* input_data = new StringStream("");
        *input_data << blob_data;

        get_object_result.ReplaceBody(input_data);
        get_object_result.SetContentLength(12);
        GetObjectOutcome get_object_outcome(std::move(get_object_result));
        callback(nullptr /*s3_client*/, get_object_request,
                 std::move(get_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.GetBlob(get_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

MATCHER_P3(HasBucketPrefixAndMarker, bucket, prefix, marker, "") {
  return ExplainMatchResult(Eq(bucket), arg.GetBucket(), result_listener) &&
         ExplainMatchResult(Eq(prefix), arg.GetPrefix(), result_listener) &&
         ExplainMatchResult(Eq(marker), arg.GetMarker(), result_listener);
}

TEST_F(AwsBlobStorageClientProviderTest, ListBlobsWithPrefix) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";

  list_blobs_metadata_context_.request->mutable_blob_metadata()
      ->set_bucket_name(bucket_name);
  list_blobs_metadata_context_.request->mutable_blob_metadata()->set_blob_name(
      blob_name);

  EXPECT_CALL(*s3_client_,
              ListObjectsAsync(
                  HasBucketPrefixAndMarker(bucket_name, blob_name, ""), _, _));

  EXPECT_THAT(provider_.ListBlobsMetadata(list_blobs_metadata_context_),
              IsSuccessful());
}

TEST_F(AwsBlobStorageClientProviderTest, ListBlobsWithMarker) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";
  std::string_view marker = "marker";

  list_blobs_metadata_context_.request->mutable_blob_metadata()
      ->set_bucket_name(bucket_name);
  list_blobs_metadata_context_.request->mutable_blob_metadata()->set_blob_name(
      blob_name);
  list_blobs_metadata_context_.request->set_page_token(marker);

  EXPECT_CALL(*s3_client_, ListObjectsAsync(HasBucketPrefixAndMarker(
                                                bucket_name, blob_name, marker),
                                            _, _));

  EXPECT_THAT(provider_.ListBlobsMetadata(list_blobs_metadata_context_),
              IsSuccessful());
}

MATCHER_P2(HasBucketAndMaxKeys, bucket, max_keys, "") {
  return ExplainMatchResult(Eq(bucket), arg.GetBucket(), result_listener) &&
         ExplainMatchResult(Eq(max_keys), arg.GetMaxKeys(), result_listener);
}

TEST_F(AwsBlobStorageClientProviderTest, ListBlobsWithMaxPageSize) {
  std::string_view bucket_name = "bucket_name";
  int page_size = 500;

  list_blobs_metadata_context_.request->mutable_blob_metadata()
      ->set_bucket_name(bucket_name);
  list_blobs_metadata_context_.request->set_max_page_size(page_size);

  EXPECT_CALL(
      *s3_client_,
      ListObjectsAsync(HasBucketAndMaxKeys(bucket_name, page_size), _, _));

  EXPECT_THAT(provider_.ListBlobsMetadata(list_blobs_metadata_context_),
              IsSuccessful());
}

TEST_F(AwsBlobStorageClientProviderTest, ListBlobsFailure) {
  std::string_view bucket_name = "bucket_name";
  list_blobs_metadata_context_.request->mutable_blob_metadata()
      ->set_bucket_name(bucket_name);
  list_blobs_metadata_context_.callback =
      [this](AsyncContext<ListBlobsMetadataRequest, ListBlobsMetadataResponse>&
                 list_blobs_metadata_context) {
        EXPECT_THAT(
            list_blobs_metadata_context.result,
            ResultIs(FailureExecutionResult(SC_AWS_INTERNAL_SERVICE_ERROR)));
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(
      *s3_client_,
      ListObjectsAsync(HasBucketPrefixAndMarker(bucket_name, "", ""), _, _))
      .WillOnce([](auto, auto callback, auto) {
        ListObjectsRequest list_objects_request;
        AWSError<S3Errors> s3_error(S3Errors::ACCESS_DENIED, false);
        ListObjectsOutcome list_objects_outcome(s3_error);
        callback(nullptr /*s3_client*/, list_objects_request,
                 std::move(list_objects_outcome), nullptr /*async_context*/);
      });

  EXPECT_THAT(provider_.ListBlobsMetadata(list_blobs_metadata_context_),
              IsSuccessful());

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

MATCHER_P2(BlobHasBucketAndName, bucket_name, blob_name, "") {
  return ExplainMatchResult(Eq(bucket_name), arg.bucket_name(),
                            result_listener) &&
         ExplainMatchResult(Eq(blob_name), arg.blob_name(), result_listener);
}

TEST_F(AwsBlobStorageClientProviderTest, ListBlobsSuccess) {
  std::string_view bucket_name = "bucket_name";
  list_blobs_metadata_context_.request->mutable_blob_metadata()
      ->set_bucket_name(bucket_name);
  list_blobs_metadata_context_.callback =
      [this, &bucket_name](
          AsyncContext<ListBlobsMetadataRequest, ListBlobsMetadataResponse>&
              list_blobs_metadata_context) {
        ASSERT_SUCCESS(list_blobs_metadata_context.result);
        EXPECT_THAT(list_blobs_metadata_context.response->blob_metadatas(),
                    ElementsAre(BlobHasBucketAndName(bucket_name, "object_1"),
                                BlobHasBucketAndName(bucket_name, "object_2")));
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(
      *s3_client_,
      ListObjectsAsync(HasBucketPrefixAndMarker(bucket_name, "", ""), _, _))
      .WillOnce([](auto, auto callback, auto) {
        ListObjectsRequest list_objects_request;
        ListObjectsResult result;
        Object object1, object2;
        object1.SetKey("object_1");
        object2.SetKey("object_2");
        result.AddContents(std::move(object1)).AddContents(std::move(object2));
        ListObjectsOutcome list_objects_outcome(std::move(result));
        callback(nullptr /*s3_client*/, list_objects_request,
                 std::move(list_objects_outcome), nullptr /*async_context*/);
      });

  EXPECT_THAT(provider_.ListBlobsMetadata(list_blobs_metadata_context_),
              IsSuccessful());

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

MATCHER_P3(HasBucketKeyAndBody, bucket_name, key, body, "") {
  std::string body_string(body.length(), 0);
  arg.GetBody()->read(body_string.data(), body_string.length());
  return ExplainMatchResult(HasBucketAndKey(bucket_name, key), arg,
                            result_listener) &&
         ExplainMatchResult(Eq(body), body_string, result_listener);
}

TEST_F(AwsBlobStorageClientProviderTest, PutBlobFailure) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";

  put_blob_context_.request->mutable_blob()
      ->mutable_metadata()
      ->set_bucket_name(bucket_name);
  put_blob_context_.request->mutable_blob()->mutable_metadata()->set_blob_name(
      blob_name);

  std::string body_str("1234567890");
  put_blob_context_.request->mutable_blob()->set_data(body_str);
  put_blob_context_.callback =
      [this](AsyncContext<PutBlobRequest, PutBlobResponse>& put_blob_context) {
        EXPECT_THAT(
            put_blob_context.result,
            ResultIs(FailureExecutionResult(SC_AWS_INTERNAL_SERVICE_ERROR)));
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(*s3_client_,
              PutObjectAsync(
                  HasBucketKeyAndBody(bucket_name, blob_name, body_str), _, _))
      .WillOnce([](auto, auto& callback, auto) {
        PutObjectRequest put_object_request;
        AWSError<S3Errors> s3_error(S3Errors::ACCESS_DENIED, false);
        PutObjectOutcome put_object_outcome(s3_error);
        callback(nullptr /*s3_client*/, put_object_request,
                 std::move(put_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.PutBlob(put_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

TEST_F(AwsBlobStorageClientProviderTest, PutBlobSuccess) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";

  put_blob_context_.request->mutable_blob()
      ->mutable_metadata()
      ->set_bucket_name(bucket_name);
  put_blob_context_.request->mutable_blob()->mutable_metadata()->set_blob_name(
      blob_name);

  std::string body_str("1234567890");
  put_blob_context_.request->mutable_blob()->set_data(body_str);
  put_blob_context_.callback =
      [this](AsyncContext<PutBlobRequest, PutBlobResponse>& put_blob_context) {
        EXPECT_SUCCESS(put_blob_context.result);
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(*s3_client_,
              PutObjectAsync(
                  HasBucketKeyAndBody(bucket_name, blob_name, body_str), _, _))
      .WillOnce([](auto, auto& callback, auto) {
        PutObjectRequest put_object_request;
        PutObjectResult result;
        PutObjectOutcome put_object_outcome(std::move(result));
        callback(nullptr /*s3_client*/, put_object_request,
                 std::move(put_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.PutBlob(put_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

TEST_F(AwsBlobStorageClientProviderTest, DeleteBlobFailure) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";

  delete_blob_context_.request->mutable_blob_metadata()->set_bucket_name(
      bucket_name);
  delete_blob_context_.request->mutable_blob_metadata()->set_blob_name(
      blob_name);
  delete_blob_context_.callback =
      [this](AsyncContext<DeleteBlobRequest, DeleteBlobResponse>&
                 delete_blob_context) {
        EXPECT_THAT(
            delete_blob_context.result,
            ResultIs(FailureExecutionResult(SC_AWS_INTERNAL_SERVICE_ERROR)));
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(*s3_client_,
              DeleteObjectAsync(HasBucketAndKey(bucket_name, blob_name), _, _))
      .WillOnce([](auto, auto callback, auto) {
        DeleteObjectRequest delete_object_request;
        AWSError<S3Errors> s3_error(S3Errors::ACCESS_DENIED, false);
        DeleteObjectOutcome delete_object_outcome(s3_error);
        callback(nullptr /*s3_client*/, delete_object_request,
                 std::move(delete_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.DeleteBlob(delete_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

TEST_F(AwsBlobStorageClientProviderTest, DeleteBlobSuccess) {
  std::string_view bucket_name = "bucket_name";
  std::string_view blob_name = "blob_name";

  delete_blob_context_.request->mutable_blob_metadata()->set_bucket_name(
      bucket_name);
  delete_blob_context_.request->mutable_blob_metadata()->set_blob_name(
      blob_name);
  delete_blob_context_.callback =
      [this](AsyncContext<DeleteBlobRequest, DeleteBlobResponse>&
                 delete_blob_context) {
        EXPECT_SUCCESS(delete_blob_context.result);
        absl::MutexLock l(&finish_called_mu_);
        finish_called_ = true;
      };

  EXPECT_CALL(*s3_client_,
              DeleteObjectAsync(HasBucketAndKey(bucket_name, blob_name), _, _))
      .WillOnce([](auto, auto callback, auto) {
        DeleteObjectRequest delete_object_request;
        DeleteObjectResult result;
        DeleteObjectOutcome delete_object_outcome(std::move(result));
        callback(nullptr /*s3_client*/, delete_object_request,
                 std::move(delete_object_outcome), nullptr /*async_context*/);
      });

  EXPECT_SUCCESS(provider_.DeleteBlob(delete_blob_context_));

  absl::MutexLock l(&finish_called_mu_);
  finish_called_mu_.Await(absl::Condition(&finish_called_));
}

}  // namespace google::scp::cpio::client_providers
