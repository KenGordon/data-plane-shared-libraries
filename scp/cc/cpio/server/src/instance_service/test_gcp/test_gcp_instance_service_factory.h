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

#ifndef CPIO_SERVER_SRC_INSTANCE_SERVICE_TEST_GCP_TEST_GCP_INSTANCE_SERVICE_FACTORY_H_
#define CPIO_SERVER_SRC_INSTANCE_SERVICE_TEST_GCP_TEST_GCP_INSTANCE_SERVICE_FACTORY_H_

#include <memory>
#include <string>

#include "core/interface/config_provider_interface.h"
#include "core/interface/service_interface.h"
#include "cpio/client_providers/interface/instance_client_provider_interface.h"
#include "cpio/server/interface/instance_service/instance_service_factory_interface.h"
#include "cpio/server/src/instance_service/gcp/gcp_instance_service_factory.h"

namespace google::scp::cpio {
struct TestGcpInstanceServiceFactoryOptions
    : public InstanceServiceFactoryOptions {
  virtual ~TestGcpInstanceServiceFactoryOptions() = default;

  TestGcpInstanceServiceFactoryOptions() {}

  TestGcpInstanceServiceFactoryOptions(
      const InstanceServiceFactoryOptions& options)
      : InstanceServiceFactoryOptions(options) {}

  std::string project_id_config_label;
  std::string zone_config_label;
  std::string instance_id_config_label;
};

/*! @copydoc GcpInstanceServiceFactory
 */
class TestGcpInstanceServiceFactory : public GcpInstanceServiceFactory {
 public:
  using GcpInstanceServiceFactory::GcpInstanceServiceFactory;

  core::ExecutionResult Init() noexcept override;

 private:
  std::shared_ptr<client_providers::InstanceClientProviderInterface>
  CreateInstanceClient() noexcept override;

  std::string project_id_;
  std::string zone_;
  std::string instance_id_;
};

}  // namespace google::scp::cpio

#endif  // CPIO_SERVER_SRC_INSTANCE_SERVICE_TEST_GCP_TEST_GCP_INSTANCE_SERVICE_FACTORY_H_
