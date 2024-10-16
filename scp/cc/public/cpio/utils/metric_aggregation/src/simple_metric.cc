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

#include "simple_metric.h"

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string_view>
#include <utility>

#include "absl/strings/str_join.h"
#include "core/common/time_provider/src/time_provider.h"
#include "core/interface/async_context.h"
#include "core/interface/async_executor_interface.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/proto/metric_service/v1/metric_service.pb.h"
#include "public/cpio/utils/metric_aggregation/interface/type_def.h"

#include "metric_utils.h"

using google::cmrt::sdk::metric_service::v1::PutMetricsRequest;
using google::cmrt::sdk::metric_service::v1::PutMetricsResponse;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncPriority;
using google::scp::core::ExecutionResult;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::Timestamp;
using google::scp::core::common::TimeProvider;
using google::scp::cpio::MetricClientInterface;
using google::scp::cpio::MetricValue;

namespace {
constexpr std::string_view kSimpleMetric = "SimpleMetric";
}  // namespace

namespace google::scp::cpio {
ExecutionResult SimpleMetric::Init() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult SimpleMetric::Run() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult SimpleMetric::Stop() noexcept {
  if (current_task_cancellation_callback_) {
    current_task_cancellation_callback_();
  }
  return SuccessExecutionResult();
}

void SimpleMetric::RunMetricPush(
    const std::shared_ptr<PutMetricsRequest> record_metric_request) noexcept {
  auto activity_id = core::common::Uuid::GenerateUuid();
  AsyncContext<PutMetricsRequest, PutMetricsResponse> record_metric_context(
      std::move(record_metric_request),
      [&](AsyncContext<PutMetricsRequest, PutMetricsResponse>& context) {
        if (!context.result.Successful()) {
          std::vector<std::string> metric_names;
          for (auto& metric : context.request->metrics()) {
            metric_names.push_back(metric.name());
          }
          SCP_CRITICAL(kSimpleMetric, object_activity_id_, context.result,
                       "PutMetrics returned a failure for '%llu' metrics. The ",
                       "metrics are: '%s'", context.request->metrics().size(),
                       absl::StrJoin(metric_names, ", ").c_str());
        }
      },
      activity_id, activity_id);
  auto metrics_count = record_metric_context.request->metrics().size();
  auto execution_result =
      metric_client_->PutMetrics(std::move(record_metric_context));
  if (!execution_result.Successful()) {
    SCP_CRITICAL(kSimpleMetric, object_activity_id_, execution_result,
                 "PutMetrics returned a failure for '%llu' metrics",
                 metrics_count);
  }
}

void SimpleMetric::Push(
    const MetricValue& metric_value,
    std::optional<std::reference_wrapper<const MetricDefinition>>
        metric_info) noexcept {
  auto record_metric_request = std::make_shared<PutMetricsRequest>();
  // if metric_info was provided for Push(), the metric will be created using
  // the provided metric_info. Otherwise, the metric will be created using the
  // predefined metric_info_ that was set when the SimpleMetric object was
  // created.
  if (metric_info) {
    MetricUtils::GetPutMetricsRequest(record_metric_request, metric_info->get(),
                                      metric_value);
  } else {
    MetricUtils::GetPutMetricsRequest(record_metric_request, metric_info_,
                                      metric_value);
  }

  auto execution_result = async_executor_->ScheduleFor(
      [this, record_metric_request]() { RunMetricPush(record_metric_request); },
      TimeProvider::GetSteadyTimestampInNanosecondsAsClockTicks(),
      current_task_cancellation_callback_);
  if (!execution_result.Successful()) {
    SCP_CRITICAL(kSimpleMetric, object_activity_id_, execution_result,
                 "Cannot schedule Metric Push for '%llu' metrics.",
                 record_metric_request->metrics().size());
  }
}

}  // namespace google::scp::cpio
