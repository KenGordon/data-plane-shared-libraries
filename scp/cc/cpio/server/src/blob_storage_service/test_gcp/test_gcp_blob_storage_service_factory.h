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

#ifndef CPIO_SERVER_SRC_BLOB_STORAGE_SERVICE_TEST_GCP_TEST_GCP_BLOB_STORAGE_SERVICE_FACTORY_H_
#define CPIO_SERVER_SRC_BLOB_STORAGE_SERVICE_TEST_GCP_TEST_GCP_BLOB_STORAGE_SERVICE_FACTORY_H_

#include <memory>

#include "cpio/server/src/blob_storage_service/gcp/gcp_blob_storage_service_factory.h"
#include "public/cpio/test/blob_storage_client/test_gcp_blob_storage_client_options.h"

namespace google::scp::cpio {
/*! @copydoc BlobStorageServiceFactoryInterface
 */
class TestGcpBlobStorageServiceFactory : public GcpBlobStorageServiceFactory {
 public:
  using GcpBlobStorageServiceFactory::GcpBlobStorageServiceFactory;

  std::shared_ptr<client_providers::BlobStorageClientProviderInterface>
  CreateBlobStorageClient() noexcept override;

 protected:
  std::shared_ptr<InstanceServiceFactoryOptions>
  CreateInstanceServiceFactoryOptions() noexcept override;

 private:
  std::shared_ptr<InstanceServiceFactoryInterface>
  CreateInstanceServiceFactory() noexcept override;

  std::shared_ptr<TestGcpBlobStorageClientOptions> test_options_ =
      std::make_shared<TestGcpBlobStorageClientOptions>();
};

}  // namespace google::scp::cpio

#endif  // CPIO_SERVER_SRC_BLOB_STORAGE_SERVICE_TEST_GCP_TEST_GCP_BLOB_STORAGE_SERVICE_FACTORY_H_
