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

#ifndef PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_MOCK_MOCK_SIMPLE_METRIC_H_
#define PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_MOCK_MOCK_SIMPLE_METRIC_H_

#include <memory>

#include "public/core/interface/execution_result.h"
#include "public/cpio/utils/metric_aggregation/interface/simple_metric_interface.h"
#include "public/cpio/utils/metric_aggregation/interface/type_def.h"

namespace google::scp::cpio {
class MockSimpleMetric : public SimpleMetricInterface {
 public:
  MockSimpleMetric() {}

  core::ExecutionResult Init() noexcept override {
    return core::SuccessExecutionResult();
  }

  core::ExecutionResult Run() noexcept override {
    return core::SuccessExecutionResult();
  }

  core::ExecutionResult Stop() noexcept override {
    return core::SuccessExecutionResult();
  }

  void Push(const MetricValue& metric_value,
            std::optional<std::reference_wrapper<const MetricDefinition>>
                metric_info = std::nullopt) noexcept override {}
};
}  // namespace google::scp::cpio

#endif  // PUBLIC_CPIO_UTILS_METRIC_AGGREGATION_MOCK_MOCK_SIMPLE_METRIC_H_
