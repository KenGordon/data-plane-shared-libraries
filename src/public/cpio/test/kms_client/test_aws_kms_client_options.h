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

#ifndef SCP_CPIO_TEST_AWS_KMS_CLIENT_OPTIONS_H_
#define SCP_CPIO_TEST_AWS_KMS_CLIENT_OPTIONS_H_

#include <memory>
#include <string>

#include "src/public/cpio/interface/kms_client/type_def.h"
#include "src/public/cpio/test/kms_client/test_aws_kms_client_options.h"

namespace google::scp::cpio {
/// BlobStorageClientOptions for testing on AWS.
struct TestAwsKmsClientOptions : public KmsClientOptions {
  std::shared_ptr<std::string> kms_endpoint_override;
};
}  // namespace google::scp::cpio

#endif  // SCP_CPIO_TEST_AWS_KMS_CLIENT_OPTIONS_H_
