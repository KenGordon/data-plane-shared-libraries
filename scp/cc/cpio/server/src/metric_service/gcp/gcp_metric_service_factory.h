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

#ifndef CPIO_SERVER_SRC_METRIC_SERVICE_GCP_GCP_METRIC_SERVICE_FACTORY_H_
#define CPIO_SERVER_SRC_METRIC_SERVICE_GCP_GCP_METRIC_SERVICE_FACTORY_H_

#include <memory>

#include "core/interface/config_provider_interface.h"
#include "cpio/client_providers/interface/metric_client_provider_interface.h"
#include "cpio/server/src/metric_service/metric_service_factory.h"
#include "public/cpio/interface/metric_client/metric_client_interface.h"

namespace google::scp::cpio {
/*! @copydoc MetricServiceFactoryInterface
 */
class GcpMetricServiceFactory : public MetricServiceFactory {
 public:
  explicit GcpMetricServiceFactory(
      const std::shared_ptr<core::ConfigProviderInterface>& config_provider)
      : MetricServiceFactory(config_provider) {}

  /**
   * @brief Creates MetricClient.
   *
   * @param config_provider provides configurations
   * @return std::shared_ptr<MetricClientInterface>
   */
  std::shared_ptr<MetricClientInterface> CreateMetricClient() noexcept override;

 private:
  std::shared_ptr<InstanceServiceFactoryInterface>
  CreateInstanceServiceFactory() noexcept override;
};
}  // namespace google::scp::cpio

#endif  // CPIO_SERVER_SRC_METRIC_SERVICE_GCP_GCP_METRIC_SERVICE_FACTORY_H_
