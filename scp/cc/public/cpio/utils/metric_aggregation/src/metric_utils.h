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

#ifndef PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_SRC_METRIC_UTILS_H_
#define PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_SRC_METRIC_UTILS_H_

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/map.h>
#include <google/protobuf/util/time_util.h>

#include "core/interface/async_executor_interface.h"
#include "cpio/client_providers/metric_client_provider/src/metric_client_utils.h"
#include "public/core/interface/execution_result.h"
#include "public/cpio/proto/metric_service/v1/metric_service.pb.h"
#include "public/cpio/utils/metric_aggregation/interface/aggregate_metric_interface.h"
#include "public/cpio/utils/metric_aggregation/interface/type_def.h"
#include "public/cpio/utils/metric_aggregation/src/aggregate_metric.h"
#include "public/cpio/utils/metric_aggregation/src/simple_metric.h"

namespace google::scp::cpio {
class MetricUtils {
 public:
  /**
   * @brief Get the PutMetricsRequest protobuf object.
   *
   * @param[out] record_metric_request
   * @param metric_info The metric definition including name, unit, and labels.
   * @param metric_value The value of the metric.
   */
  static void GetPutMetricsRequest(
      std::shared_ptr<cmrt::sdk::metric_service::v1::PutMetricsRequest>&
          record_metric_request,
      const MetricDefinition& metric_info,
      const MetricValue& metric_value) noexcept;

  /**
   * @brief Registers a simple metric with MetricClient.
   *
   * @param async_executor
   * @param metric_client
   * @param metric_name_str Name of the metric
   * @param metric_label_component Component Name where the metric is emitted
   * @param metric_label_method Method Name where the metric is emitted
   * @param metric_unit_type unit type
   * @return std::shared_ptr<SimpleMetricInterface>
   */
  static std::shared_ptr<SimpleMetricInterface> RegisterSimpleMetric(
      const std::shared_ptr<core::AsyncExecutorInterface>& async_executor,
      const std::shared_ptr<MetricClientInterface>& metric_client,
      std::string_view metric_name_str,
      std::string_view metric_label_component_str,
      std::string_view metric_label_method_str,
      MetricUnit metric_unit_type) noexcept;

  /**
   * @brief Registers a aggregate metric with MetricClient.
   *
   * @param async_executor
   * @param metric_client
   * @param metric_name_str Name of the metric
   * @param metric_label_component Component Name where the metric is emitted
   * @param metric_label_method Method Name where the metric is emitted
   * @param metric_unit_type unit type
   * @param metric_event_labels Dimension labels of the metric
   * @param aggregated_metric_interval_ms Aggregation interval
   * @return std::shared_ptr<AggregateMetricInterface>
   */
  static std::shared_ptr<AggregateMetricInterface> RegisterAggregateMetric(
      const std::shared_ptr<core::AsyncExecutorInterface>& async_executor,
      const std::shared_ptr<MetricClientInterface>& metric_client,
      std::string_view metric_name_str, std::string_view metric_label_component,
      std::string_view metric_label_method, MetricUnit metric_unit_type,
      std::vector<std::string> metric_event_labels,
      size_t aggregated_metric_interval_ms) noexcept;

  /**
   * @brief Create a Metric Labels With Component Signature object
   *
   * @param component_name the component name value for metric label
   * `ComponentName`.
   * @param method_name the method name value for metric label `MethodName`.
   * @return MetricLabels a map of metric labels.
   */
  static MetricLabels CreateMetricLabelsWithComponentSignature(
      std::string component_name,
      std::string method_name = std::string()) noexcept;
};

}  // namespace google::scp::cpio

#endif  // PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_SRC_METRIC_UTILS_H_
