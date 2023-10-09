// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "src/cpp/encryption/key_fetcher/src/public_key_fetcher.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/util/time_util.h>

#include "absl/random/distributions.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "glog/logging.h"
#include "scp/cc/core/interface/errors.h"
#include "scp/cc/public/core/interface/execution_result.h"
#include "scp/cc/public/cpio/interface/public_key_client/public_key_client_interface.h"
#include "scp/cc/public/cpio/interface/public_key_client/type_def.h"
#include "src/cpp/encryption/key_fetcher/src/key_fetcher_utils.h"

namespace privacy_sandbox::server_common {

using ::google::scp::core::ExecutionResult;
using ::google::scp::core::FailureExecutionResult;
using ::google::scp::core::SuccessExecutionResult;
using ::google::scp::core::errors::GetErrorMessage;

using ::google::cmrt::sdk::public_key_service::v1::ListPublicKeysRequest;
using ::google::cmrt::sdk::public_key_service::v1::ListPublicKeysResponse;
using ::google::cmrt::sdk::public_key_service::v1::PublicKey;
using ::google::protobuf::util::TimeUtil;
using ::google::scp::cpio::PublicKeyClientInterface;
using ::google::scp::cpio::PublicKeyClientOptions;
using ::google::scp::cpio::PublicPrivateKeyPairId;
using ::google::scp::cpio::Timestamp;

static constexpr absl::string_view kKeyFetchFailMessage =
    "ListPublicKeys call failed (status_code: %s)";
static constexpr absl::string_view kKeyFetchSuccessMessage =
    "Successfully fetched latest public keys: (key IDs: [%s], expiration time: "
    "%s)";

PublicKeyFetcher::PublicKeyFetcher(
    absl::flat_hash_map<
        CloudPlatform,
        std::unique_ptr<google::scp::cpio::PublicKeyClientInterface>>
        public_key_clients)
    : public_key_clients_(std::move(public_key_clients)) {}

PublicKeyFetcher::~PublicKeyFetcher() {
  for (const auto& [cloud_platform, public_key_client] : public_key_clients_) {
    public_key_client->Stop();
  }
}

/**
 * Makes a blocking call to fetch the public keys using the public key client.
 * UnavailableError status will be returned in case of failure.
 */
absl::Status PublicKeyFetcher::Refresh() noexcept ABSL_LOCKS_EXCLUDED(mutex_) {
  VLOG(3) << "Refreshing public keys...";
  absl::Notification public_key_fetch_notification;

  for (const auto& [cloud_platform, public_key_client] : public_key_clients_) {
    ExecutionResult result = public_key_client->ListPublicKeys(
        ListPublicKeysRequest(),
        [this, &public_key_fetch_notification, platform = cloud_platform](
            ExecutionResult execution_result, ListPublicKeysResponse response) {
          VLOG(3) << "List public keys call finished.";

          if (execution_result.Successful()) {
            {
              absl::MutexLock l(&mutex_);
              public_keys_[platform] = std::vector<PublicKey>();
              for (const auto& key : response.public_keys()) {
                PublicKey copy;
                copy.set_key_id(ToOhttpKeyId(key.key_id()));
                copy.set_public_key(key.public_key());
                public_keys_[platform].push_back(copy);
              }
            }

            std::vector<PublicPrivateKeyPairId> key_ids = GetKeyIds(platform);
            std::string key_ids_str = absl::StrJoin(key_ids, ", ");
            VLOG(3) << absl::StrFormat(
                kKeyFetchSuccessMessage, key_ids_str,
                TimeUtil::ToString(response.expiration_time()));
            VLOG(3) << "Public key refresh flow completed successfully. ";
          } else {
            VLOG(1) << absl::StrFormat(
                kKeyFetchFailMessage,
                GetErrorMessage(execution_result.status_code));
          }

          public_key_fetch_notification.Notify();
        });

    if (!result.Successful()) {
      std::string error = absl::StrFormat(kKeyFetchFailMessage,
                                          GetErrorMessage(result.status_code));
      VLOG(1) << error;
      return absl::UnavailableError(error);
    }
  }

  public_key_fetch_notification.WaitForNotification();
  return absl::OkStatus();
}

absl::StatusOr<PublicKey> PublicKeyFetcher::GetKey(
    CloudPlatform cloud_platform) noexcept ABSL_LOCKS_EXCLUDED(mutex_) {
  absl::MutexLock l(&mutex_);
  if (public_keys_.empty()) {
    return absl::FailedPreconditionError("No public keys to return.");
  }

  int index =
      absl::Uniform(absl::IntervalClosedOpen, bitgen_, 0,
                    static_cast<int>(public_keys_[cloud_platform].size()));
  return public_keys_[cloud_platform].at(index);
}

std::vector<PublicPrivateKeyPairId> PublicKeyFetcher::GetKeyIds(
    CloudPlatform cloud_platform) noexcept ABSL_LOCKS_EXCLUDED(mutex_) {
  absl::MutexLock l(&mutex_);
  std::vector<PublicPrivateKeyPairId> key_pair_ids;
  for (const auto& key : public_keys_[cloud_platform]) {
    key_pair_ids.push_back(std::string(key.key_id()));
  }

  return key_pair_ids;
}

std::unique_ptr<PublicKeyFetcherInterface> PublicKeyFetcherFactory::Create(
    const absl::flat_hash_map<
        CloudPlatform,
        std::vector<google::scp::cpio::PublicKeyVendingServiceEndpoint>>&
        per_platform_endpoints) {
  absl::flat_hash_map<
      CloudPlatform,
      std::unique_ptr<google::scp::cpio::PublicKeyClientInterface>>
      public_key_clients;

  for (const auto& [cloud_platform, endpoints] : per_platform_endpoints) {
    PublicKeyClientOptions options;
    options.endpoints = endpoints;

    std::unique_ptr<PublicKeyClientInterface> public_key_client =
        google::scp::cpio::PublicKeyClientFactory::Create(std::move(options));

    ExecutionResult init_result = public_key_client->Init();
    if (!init_result.Successful()) {
      VLOG(1) << "Failed to initialize public key client.";
    }

    ExecutionResult run_result = public_key_client->Run();
    if (!run_result.Successful()) {
      VLOG(1) << "Failed to run public key client.";
    }

    public_key_clients[cloud_platform] = std::move(public_key_client);
  }

  return std::make_unique<PublicKeyFetcher>(std::move(public_key_clients));
}

}  // namespace privacy_sandbox::server_common
