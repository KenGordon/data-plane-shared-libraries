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

#pragma once

namespace google::scp::cpio {
// Optional. Only needed for AWS. If not set, use the default value us-east-1.
static constexpr char kTestAwsAutoScalingClientRegion[] =
    "cmrt_sdk_test_aws_auto_scaling_client_region";
// Optional. Only needed for integration test.
static constexpr char kTestAutoScalingClientCloudEndpointOverride[] =
    "cmrt_sdk_test_auto_scaling_client_cloud_endpoint_override";
}  // namespace google::scp::cpio
