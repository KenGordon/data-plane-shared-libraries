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

#ifndef CPIO_CLIENT_PROVIDERS_METRIC_CLIENT_PROVIDER_SRC_AWS_AWS_METRIC_CLIENT_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_METRIC_CLIENT_PROVIDER_SRC_AWS_AWS_METRIC_CLIENT_PROVIDER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <aws/monitoring/CloudWatchClient.h>
#include <aws/monitoring/model/PutMetricDataRequest.h>

#include "scp/cc/core/interface/async_context.h"
#include "scp/cc/core/interface/async_executor_interface.h"
#include "scp/cc/core/interface/message_router_interface.h"
#include "scp/cc/cpio/client_providers/interface/instance_client_provider_interface.h"
#include "scp/cc/cpio/client_providers/metric_client_provider/src/metric_client_provider.h"
#include "scp/cc/public/core/interface/execution_result.h"
#include "scp/cc/public/cpio/interface/metric_client/type_def.h"
#include "scp/cc/public/cpio/proto/metric_service/v1/metric_service.pb.h"

#include "error_codes.h"

namespace google::scp::cpio::client_providers {
/*! @copydoc MetricClientProvider
 */
class AwsMetricClientProvider : public MetricClientProvider {
 public:
  /**
   * @brief Constructs a new Aws Metric Client Provider.
   *
   * @param metric_client_options the configurations for Metric Client.
   * @param instance_client_provider the Instance Client Provider.
   * @param region the optional region input. A temporary solution for PBS.
   * @param async_executor the thread pool for batch recording.
   * @param io_async_executor the thread pool to replace aws thread pool.
   */
  explicit AwsMetricClientProvider(
      MetricClientOptions metric_client_options,
      InstanceClientProviderInterface* instance_client_provider,
      core::AsyncExecutorInterface* async_executor,
      core::AsyncExecutorInterface* io_async_executor,
      MetricBatchingOptions metric_batching_options = MetricBatchingOptions())
      : MetricClientProvider(async_executor, std::move(metric_client_options),
                             instance_client_provider,
                             std::move(metric_batching_options)),
        io_async_executor_(io_async_executor) {}

  core::ExecutionResult Run() noexcept override;

 protected:
  core::ExecutionResult MetricsBatchPush(
      const std::shared_ptr<std::vector<core::AsyncContext<
          cmrt::sdk::metric_service::v1::PutMetricsRequest,
          cmrt::sdk::metric_service::v1::PutMetricsResponse>>>&
          metric_requests_vector) noexcept override;

  /**
   * @brief Creates a Client Configuration object.
   *
   * @param region input region.
   * @param client_config returned Client Configuration.
   */
  virtual void CreateClientConfiguration(
      const std::string& region,
      Aws::Client::ClientConfiguration& client_config) noexcept;

  /// CloudWatchClient.
  std::optional<Aws::CloudWatch::CloudWatchClient> cloud_watch_client_;

 private:
  /**
   * @brief Is called after AWS PutMetricDataAsync is completed.
   *
   * @param metric_requests_vector the vector of record custom metric operation
   * context in PutMetricDataAsyncCall.
   * @param outcome the operation outcome of AWS PutMetricDataAsync.
   */
  void OnPutMetricDataAsyncCallback(
      std::vector<
          core::AsyncContext<cmrt::sdk::metric_service::v1::PutMetricsRequest,
                             cmrt::sdk::metric_service::v1::PutMetricsResponse>>
          metric_requests_vector,
      const Aws::CloudWatch::CloudWatchClient*,
      const Aws::CloudWatch::Model::PutMetricDataRequest&,
      const Aws::CloudWatch::Model::PutMetricDataOutcome& outcome,
      const std::shared_ptr<const Aws::Client::AsyncCallerContext>&) noexcept;

  /// An instance of the IO async executor.
  core::AsyncExecutorInterface* io_async_executor_;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_METRIC_CLIENT_PROVIDER_SRC_AWS_AWS_METRIC_CLIENT_PROVIDER_H_
