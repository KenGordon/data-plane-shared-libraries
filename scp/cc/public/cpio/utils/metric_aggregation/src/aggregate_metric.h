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

#ifndef PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_SRC_AGGREGATE_METRIC_H_
#define PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_SRC_AGGREGATE_METRIC_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "core/interface/async_context.h"
#include "core/interface/async_executor_interface.h"
#include "cpio/client_providers/interface/metric_client_provider_interface.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/interface/metric_client/metric_client_interface.h"
#include "public/cpio/proto/metric_service/v1/metric_service.pb.h"
#include "public/cpio/utils/metric_aggregation/interface/aggregate_metric_interface.h"
#include "public/cpio/utils/metric_aggregation/interface/type_def.h"

#include "error_codes.h"

namespace google::scp::cpio {
/*! @copydoc AggregateMetricInterface
 */
class AggregateMetric : public AggregateMetricInterface {
 public:
  explicit AggregateMetric(
      const std::shared_ptr<core::AsyncExecutorInterface>& async_executor,
      const std::shared_ptr<MetricClientInterface>& metric_client,
      MetricDefinition metric_info,
      core::TimeDuration push_interval_duration_in_ms);

  explicit AggregateMetric(
      const std::shared_ptr<core::AsyncExecutorInterface>& async_executor,
      const std::shared_ptr<MetricClientInterface>& metric_client,
      MetricDefinition metric_info,
      core::TimeDuration push_interval_duration_in_ms,
      const std::vector<std::string>& event_code_labels_list,
      const std::string& event_code_label_key = kEventCodeLabelKey);

  core::ExecutionResult Init() noexcept override;

  core::ExecutionResult Run() noexcept override
      ABSL_LOCKS_EXCLUDED(task_schedule_mutex_);

  core::ExecutionResult Stop() noexcept override
      ABSL_LOCKS_EXCLUDED(task_schedule_mutex_);

  core::ExecutionResult Increment(
      const std::string& event_code = std::string()) noexcept override
      ABSL_LOCKS_EXCLUDED(task_schedule_mutex_);

  core::ExecutionResult IncrementBy(
      uint64_t value,
      const std::string& event_code = std::string()) noexcept override
      ABSL_LOCKS_EXCLUDED(task_schedule_mutex_);

 protected:
  /**
   * @brief Runs the actual metric push logic for one counter data.
   *
   * @param counter the counter number to be the metric value.
   * @param metric_info Metric info specifies the metric's name, unit,
   * namespace, and labels.
   */
  virtual void MetricPushHandler(int64_t counter,
                                 const MetricDefinition& metric_info) noexcept;

  /**
   * @brief Goes over all counters and push metric when the counter has valid
   * value. Also reset some counters. This operation must be error free to
   * avoid memory increases overtime. In the case of errors an alert must be
   * raised.
   */
  virtual void RunMetricPush() noexcept
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(task_schedule_mutex_);

  /**
   * @brief Schedules a round of metric push in the next time_duration_.
   *
   * @return core::ExecutionResult
   */
  virtual core::ExecutionResult ScheduleMetricPush() noexcept
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(task_schedule_mutex_);

  /// The map contains the event codes paired with its counter. The
  /// event_counter is associated with the event_code.
  /// Use `node_hash_map` because value type is not movable.
  absl::flat_hash_map<std::string, size_t> event_counters_
      ABSL_GUARDED_BY(task_schedule_mutex_);

  /// The map contains the event codes paired with its metric definition.
  absl::flat_hash_map<std::string, const MetricDefinition> event_metric_infos_;

  /// An instance to the async executor.
  std::shared_ptr<core::AsyncExecutorInterface> async_executor_;
  /// Metric client instance.
  std::shared_ptr<MetricClientInterface> metric_client_;
  /// Metric general information.
  const MetricDefinition metric_info_;

  /// The time duration of the aggregated metric push interval in milliseconds.
  core::TimeDuration push_interval_duration_in_ms_;

  /// The default counter in AggregateMetric. This counter doesn't have
  /// event_code or metric_tag, and it defined by metric_info_ only. When
  /// construct AggregateMetric without event_code_labels_list, this is the only
  /// default counter in AggregateMetric.
  size_t counter_ ABSL_GUARDED_BY(task_schedule_mutex_);

  /// The cancellation callback.
  std::function<bool()> current_cancellation_callback_;

  /// Indicates whether the component stopped
  bool is_running_ ABSL_GUARDED_BY(task_schedule_mutex_);

  /// Indicates whether the component can take metric increments. Exclusively
  /// used for mocking.
  bool can_accept_incoming_increments_;

  static constexpr char kEventCodeLabelKey[] = "EventCode";

  /// @brief activity ID for the lifetime of the object
  const core::common::Uuid object_activity_id_;

  /// Number of pending requests. Used to ensure no callbacks are scheduled with
  /// dangling pointers to this object.
  int num_pending_requests_ ABSL_GUARDED_BY(task_schedule_mutex_) = 0;

  /// @brief mutex to protect scheduling new tasks while stopping the component
  absl::Mutex task_schedule_mutex_;
};
}  // namespace google::scp::cpio

#endif  // PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_SRC_AGGREGATE_METRIC_H_
