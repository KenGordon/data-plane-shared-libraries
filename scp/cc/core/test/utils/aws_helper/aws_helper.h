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

#ifndef CORE_TEST_UTILS_AWS_HELPER_AWS_HELPER_H_
#define CORE_TEST_UTILS_AWS_HELPER_AWS_HELPER_H_

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/CreateTableRequest.h>
#include <aws/kms/KMSClient.h>
#include <aws/s3/S3Client.h>
#include <aws/ssm/SSMClient.h>

namespace google::scp::core::test {
/// Default AWS region to create clients.
constexpr char kDefaultRegion[] = "us-east-1";

std::shared_ptr<Aws::DynamoDB::DynamoDBClient> CreateDynamoDbClient(
    std::string_view endpoint, std::string_view region = kDefaultRegion);

void CreateTable(
    const std::shared_ptr<Aws::DynamoDB::DynamoDBClient>& dynamo_db_client,
    std::string_view table_name,
    const std::vector<Aws::DynamoDB::Model::AttributeDefinition>& attributes,
    const std::vector<Aws::DynamoDB::Model::KeySchemaElement>& schemas);

std::shared_ptr<Aws::S3::S3Client> CreateS3Client(
    std::string_view endpoint, std::string_view region = kDefaultRegion);

std::shared_ptr<Aws::KMS::KMSClient> CreateKMSClient(
    std::string_view endpoint, std::string_view region = kDefaultRegion);

void CreateBucket(const std::shared_ptr<Aws::S3::S3Client>& s3_client,
                  std::string_view bucket_name);

std::shared_ptr<Aws::SSM::SSMClient> CreateSSMClient(
    std::string_view endpoint, std::string_view region = kDefaultRegion);

void PutParameter(const std::shared_ptr<Aws::SSM::SSMClient>& ssm_client,
                  std::string_view parameter_name,
                  std::string_view parameter_value);

std::string GetParameter(const std::shared_ptr<Aws::SSM::SSMClient>& ssm_client,
                         std::string_view parameter_name);

void CreateKey(const std::shared_ptr<Aws::KMS::KMSClient>& kms_client,
               std::string& key_id, std::string& key_resource_name);

std::string Encrypt(const std::shared_ptr<Aws::KMS::KMSClient>& kms_client,
                    std::string_view key_id, std::string_view plaintext);
}  // namespace google::scp::core::test

#endif  // CORE_TEST_UTILS_AWS_HELPER_AWS_HELPER_H_
