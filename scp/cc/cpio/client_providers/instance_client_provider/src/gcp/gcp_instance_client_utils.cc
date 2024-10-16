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

#include "gcp_instance_client_utils.h"

#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "core/common/uuid/src/uuid.h"
#include "core/interface/http_types.h"
#include "public/core/interface/execution_result.h"

#include "error_codes.h"

using google::scp::core::ExecutionResult;
using google::scp::core::ExecutionResultOr;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::
    SC_GCP_INSTANCE_CLIENT_INVALID_INSTANCE_RESOURCE_NAME;

namespace {
constexpr char kGcpInstanceClientUtils[] = "GcpInstanceClientUtils";

// Valid GCP instance resource name format:
// `//compute.googleapis.com/projects/{PROJECT_ID}/zones/{ZONE_ID}/instances/{INSTANCE_ID}`
constexpr char kInstanceResourceNameRegex[] =
    R"(//compute.googleapis.com/projects\/([a-z0-9][a-z0-9-]{5,29})\/zones\/([a-z][a-z0-9-]{5,29})\/instances\/(\d+))";
constexpr char kInstanceResourceNamePrefix[] = R"(//compute.googleapis.com/)";

// GCP listing all tags attached to a resource has two kinds of urls.
// For non-location tied resource, like project, it is
// https://cloudresourcemanager.googleapis.com/v3/tagBindings;
// For location tied resource, like COMPUTE ENGINE instance, it is
// https://LOCATION-cloudresourcemanager.googleapis.com/v3/tagBindings
// For more information, see:
// https://cloud.google.com/resource-manager/docs/tags/tags-creating-and-managing#listing_tags
constexpr char kResourceManagerUriFormat[] =
    "https://%scloudresourcemanager.googleapis.com/v3/tagBindings";
constexpr char kLocationsTag[] = "locations";
constexpr char kZonesTag[] = "zones";
constexpr char kRegionsTag[] = "regions";
}  // namespace

namespace google::scp::cpio::client_providers {

ExecutionResultOr<std::string> GcpInstanceClientUtils::GetCurrentProjectId(
    const std::shared_ptr<InstanceClientProviderInterface>&
        instance_client) noexcept {
  std::string instance_resource_name;
  RETURN_AND_LOG_IF_FAILURE(instance_client->GetCurrentInstanceResourceNameSync(
                                instance_resource_name),
                            kGcpInstanceClientUtils, kZeroUuid,
                            "Failed getting instance resource name.");

  auto project_id_or =
      ParseProjectIdFromInstanceResourceName(instance_resource_name);
  RETURN_AND_LOG_IF_FAILURE(
      project_id_or.result(), kGcpInstanceClientUtils, kZeroUuid,
      "Failed to parse instance resource name %s to get project ID",
      instance_resource_name.c_str());

  return std::move(*project_id_or);
}

ExecutionResultOr<std::string>
GcpInstanceClientUtils::ParseProjectIdFromInstanceResourceName(
    std::string_view resource_name) noexcept {
  GcpInstanceResourceNameDetails details;
  RETURN_AND_LOG_IF_FAILURE(
      GetInstanceResourceNameDetails(resource_name, details),
      kGcpInstanceClientUtils, kZeroUuid,
      "Failed to get instance resource name details for %s",
      resource_name.data());
  return std::move(details.project_id);
}

ExecutionResultOr<std::string>
GcpInstanceClientUtils::ParseZoneIdFromInstanceResourceName(
    std::string_view resource_name) noexcept {
  GcpInstanceResourceNameDetails details;
  RETURN_AND_LOG_IF_FAILURE(
      GetInstanceResourceNameDetails(resource_name, details),
      kGcpInstanceClientUtils, kZeroUuid,
      "Failed to get instance resource name details for %s",
      resource_name.data());
  return std::move(details.zone_id);
}

ExecutionResultOr<std::string>
GcpInstanceClientUtils::ParseInstanceIdFromInstanceResourceName(
    std::string_view resource_name) noexcept {
  GcpInstanceResourceNameDetails details;
  RETURN_AND_LOG_IF_FAILURE(
      GetInstanceResourceNameDetails(resource_name, details),
      kGcpInstanceClientUtils, kZeroUuid,
      "Failed to get instance resource name details for %s",
      resource_name.data());
  return std::move(details.instance_id);
}

ExecutionResult GcpInstanceClientUtils::ValidateInstanceResourceNameFormat(
    std::string_view resource_name) noexcept {
  std::regex re(kInstanceResourceNameRegex);
  if (!std::regex_match(std::string{resource_name}, re)) {
    auto result = FailureExecutionResult(
        SC_GCP_INSTANCE_CLIENT_INVALID_INSTANCE_RESOURCE_NAME);
    RETURN_AND_LOG_IF_FAILURE(
        result, kGcpInstanceClientUtils, kZeroUuid,
        "Resource name %s doesn't match the expected regex.",
        resource_name.data());
  }

  return SuccessExecutionResult();
}

ExecutionResult GcpInstanceClientUtils::GetInstanceResourceNameDetails(
    std::string_view resource_name,
    GcpInstanceResourceNameDetails& detail) noexcept {
  RETURN_AND_LOG_IF_FAILURE(ValidateInstanceResourceNameFormat(resource_name),
                            kGcpInstanceClientUtils, kZeroUuid,
                            "Resource name %s is invalid.",
                            resource_name.data());

  const std::string_view resource_id =
      resource_name.substr(std::strlen(kInstanceResourceNamePrefix));
  // Splits `projects/project_abc1/zones/us-west1/instances/12345678987654321`
  // to { projects,project_abc1,zones,us-west1,instances,12345678987654321 }
  std::vector<std::string> splits = absl::StrSplit(resource_id, "/");
  detail.project_id = splits[1];
  detail.zone_id = splits[3];
  detail.instance_id = splits[5];

  return SuccessExecutionResult();
}

// TODO: Add a Resource name validation function

std::string GcpInstanceClientUtils::CreateRMListTagsUrl(
    std::string_view resource_name) noexcept {
  std::vector<std::string> splits = absl::StrSplit(resource_name, "/");
  auto i = 0;
  while (i < splits.size()) {
    const auto& part = splits.at(i);
    if (part == kZonesTag || part == kLocationsTag || part == kRegionsTag) {
      const auto& location = splits.at(i + 1);

      return absl::StrFormat(kResourceManagerUriFormat,
                             absl::StrCat(location, "-"));
    }
    i++;
  }
  return absl::StrFormat(kResourceManagerUriFormat, "");
}
}  // namespace google::scp::cpio::client_providers
