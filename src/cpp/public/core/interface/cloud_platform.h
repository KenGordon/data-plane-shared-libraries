/*
 * Copyright 2023 Google LLC
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

#ifndef SRC_CPP_PUBLIC_CORE_INTERFACE_CLOUD_PLATFORM_H_
#define SRC_CPP_PUBLIC_CORE_INTERFACE_CLOUD_PLATFORM_H_

namespace privacy_sandbox::server_common {

// Declare cloud platforms supported.
// Need to update key refresh monitoring code in src/cpp/metric/key_fetch.h when
// adding a new cloud platform. CloudPlatform::kLocal is not needed for
// monitoring's purpose.
enum class CloudPlatform {
  kLocal,
  kGcp,
  kAws,
};

}  // namespace privacy_sandbox::server_common

#endif  // SRC_CPP_PUBLIC_CORE_INTERFACE_CLOUD_PLATFORM_H_
