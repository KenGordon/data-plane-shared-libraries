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

#ifndef CPIO_SERVER_SRC_BLOB_STORAGE_SERVICE_BLOB_STORAGE_SERVICE_FACTORY_H_
#define CPIO_SERVER_SRC_BLOB_STORAGE_SERVICE_BLOB_STORAGE_SERVICE_FACTORY_H_

#include <memory>

#include "core/interface/config_provider_interface.h"
#include "cpio/client_providers/interface/blob_storage_client_provider_interface.h"
#include "cpio/server/interface/blob_storage_service/blob_storage_service_factory_interface.h"
#include "cpio/server/interface/instance_service/instance_service_factory_interface.h"

namespace google::scp::cpio {
/// Base class for setting up protected members.
class BlobStorageServiceFactory : public BlobStorageServiceFactoryInterface {
 public:
  explicit BlobStorageServiceFactory(
      std::shared_ptr<core::ConfigProviderInterface> config_provider)
      : config_provider_(config_provider) {}

  core::ExecutionResult Init() noexcept override;

  core::ExecutionResult Run() noexcept override;

  core::ExecutionResult Stop() noexcept override;

 protected:
  virtual std::shared_ptr<InstanceServiceFactoryOptions>
  CreateInstanceServiceFactoryOptions() noexcept;

  std::shared_ptr<core::ConfigProviderInterface> config_provider_;

  std::shared_ptr<client_providers::InstanceClientProviderInterface>
      instance_client_;

  std::shared_ptr<InstanceServiceFactoryInterface> instance_service_factory_;
  std::shared_ptr<InstanceServiceFactoryOptions>
      instance_service_factory_options_;

 private:
  virtual std::shared_ptr<InstanceServiceFactoryInterface>
  CreateInstanceServiceFactory() noexcept = 0;
};

}  // namespace google::scp::cpio

#endif  // CPIO_SERVER_SRC_BLOB_STORAGE_SERVICE_BLOB_STORAGE_SERVICE_FACTORY_H_
