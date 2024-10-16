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

#include "gcp_metric_client_utils.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <google/protobuf/util/time_util.h>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "core/interface/async_context.h"
#include "google/cloud/future.h"
#include "google/cloud/monitoring/metric_client.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/proto/metric_service/v1/metric_service.pb.h"

#include "error_codes.h"

using google::api::MonitoredResource;
using google::cloud::future;
using google::cloud::Status;
using google::cloud::StatusCode;
using google::cmrt::sdk::metric_service::v1::PutMetricsRequest;
using google::cmrt::sdk::metric_service::v1::PutMetricsResponse;
using google::monitoring::v3::TimeSeries;
using google::protobuf::util::TimeUtil;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::errors::
    SC_GCP_METRIC_CLIENT_FAILED_OVERSIZE_METRIC_LABELS;
using google::scp::core::errors::
    SC_GCP_METRIC_CLIENT_FAILED_WITH_INVALID_TIMESTAMP;
using google::scp::core::errors::SC_GCP_METRIC_CLIENT_INVALID_METRIC_VALUE;

/// Prefix of the metric type for all custom metrics.
static constexpr char kCustomMetricTypePrefix[] = "custom.googleapis.com";
/// Prefix of project name.
static constexpr char kProjectNamePrefix[] = "projects/";
static constexpr char kResourceType[] = "gce_instance";
static constexpr char kProjectIdKey[] = "project_id";
static constexpr char kInstanceIdKey[] = "instance_id";
static constexpr char kInstanceZoneKey[] = "zone";
// The limit of GCP metric labels size is 30.
static constexpr size_t kGcpMetricLabelsSizeLimit = 30;

static constexpr int k25HoursSecondsCount =
    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(25))
        .count();
static constexpr int k5MinsSecondsCount =
    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes(5))
        .count();

namespace google::scp::cpio::client_providers {

ExecutionResult GcpMetricClientUtils::ParseRequestToTimeSeries(
    AsyncContext<PutMetricsRequest, PutMetricsResponse>& record_metric_context,
    std::string_view name_space,
    std::vector<TimeSeries>& time_series_list) noexcept {
  for (auto i = 0; i < record_metric_context.request->metrics().size(); ++i) {
    auto& time_series = time_series_list.emplace_back();

    auto metric = record_metric_context.request->metrics()[i];
    if (metric.labels().size() > kGcpMetricLabelsSizeLimit) {
      return FailureExecutionResult(
          SC_GCP_METRIC_CLIENT_FAILED_OVERSIZE_METRIC_LABELS);
    }

    auto input_timestamp_in_ms =
        TimeUtil::TimestampToMilliseconds(metric.timestamp());
    if (input_timestamp_in_ms < 0) {
      return FailureExecutionResult(
          SC_GCP_METRIC_CLIENT_FAILED_WITH_INVALID_TIMESTAMP);
    }

    auto timestamp = TimeUtil::GetCurrentTime();
    if (input_timestamp_in_ms > 0) {
      auto request_timestamp =
          TimeUtil::MillisecondsToTimestamp(input_timestamp_in_ms);
      auto difference =
          TimeUtil::DurationToSeconds(timestamp - request_timestamp);

      // The valid timestamp of gcp custom metric cannot be earlier than 25
      // hours or later than 5 mins.
      if (difference > k25HoursSecondsCount ||
          difference < -k5MinsSecondsCount) {
        return FailureExecutionResult(
            SC_GCP_METRIC_CLIENT_FAILED_WITH_INVALID_TIMESTAMP);
      }
      timestamp = request_timestamp;
    }

    time_series.mutable_metric()->mutable_labels()->insert(
        metric.labels().begin(), metric.labels().end());
    time_series.mutable_metric()->set_type(absl::StrCat(
        kCustomMetricTypePrefix, "/", name_space, "/", metric.name()));

    auto* point = time_series.add_points();

    double metric_value = 0.0;
    if (!absl::SimpleAtod(std::string_view(metric.value()), &metric_value)) {
      return FailureExecutionResult(SC_GCP_METRIC_CLIENT_INVALID_METRIC_VALUE);
    }

    point->mutable_value()->set_double_value(metric_value);
    point->mutable_interval()->mutable_end_time()->CopyFrom(timestamp);
  }

  return SuccessExecutionResult();
}

std::string GcpMetricClientUtils::ConstructProjectName(
    std::string_view project_id) {
  return absl::StrCat(kProjectNamePrefix, project_id);
}

void GcpMetricClientUtils::AddResourceToTimeSeries(
    std::string_view project_id, std::string_view instance_id,
    std::string_view instance_zone,
    std::vector<TimeSeries>& time_series_list) noexcept {
  MonitoredResource resource;
  resource.set_type(kResourceType);
  auto& labels = *resource.mutable_labels();
  labels[std::string(kProjectIdKey)] = std::string{project_id};
  labels[std::string(kInstanceIdKey)] = std::string{instance_id};
  labels[std::string(kInstanceZoneKey)] = std::string{instance_zone};

  for (auto& time_series : time_series_list) {
    time_series.mutable_resource()->CopyFrom(resource);
  }
}

}  // namespace google::scp::cpio::client_providers
