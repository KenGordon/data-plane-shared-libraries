/*
 * Copyright 2023 Google LLC
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

#ifndef ROMA_GRPC_SERVER_NATIVE_FUNCTION_GRPC_SERVER_H_
#define ROMA_GRPC_SERVER_NATIVE_FUNCTION_GRPC_SERVER_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "src/core/common/uuid/uuid.h"
#include "src/roma/native_function_grpc_server/interface.h"
#include "src/roma/sandbox/native_function_binding/thread_safe_map.h"

namespace google::scp::roma::grpc_server {
using roma::sandbox::native_function_binding::ThreadSafeMap;

template <typename TMetadata = std::string>
class NativeFunctionGrpcServer final {
 public:
  NativeFunctionGrpcServer() = delete;

  explicit NativeFunctionGrpcServer(
      const std::vector<std::string>& server_addresses) {
    for (const auto& addr : server_addresses) {
      builder_.AddListeningPort(addr, grpc::InsecureServerCredentials());
    }
  }

  ~NativeFunctionGrpcServer() {
    // Always shutdown the completion queue after the server.
    completion_queue_->Shutdown();
    DrainQueue(completion_queue_.get());
  }

  void Shutdown() { server_->Shutdown(); }

  /** @brief Adds a gRPC service to server for invocation of RPCs from arbitrary
    services. Lifetime of service is managed externally, for RomaService, is
    managed by Config.
   */
  void AddService(grpc::Service* service) { builder_.RegisterService(service); }

  /** @brief Stores pointer to vector of factory functions on server for
   * generation of RequestHandlerImpl<TMetadata, THandler> instances, allowing
   * completion queue to handle arbitrary RPCs in HandleRpcs. Lifetime of
   factories vector is managed externally, for RomaService, is managed by
   Config.
   */
  void AddFactories(
      std::vector<grpc_server::FactoryFunction<TMetadata>>* factories) {
    factories_ = factories;
  }

  absl::Status StoreMetadata(std::string uuid, TMetadata metadata) {
    return metadata_map_.Add(std::move(uuid), std::move(metadata));
  }

  void DeleteMetadata(std::string_view uuid) { metadata_map_.Delete(uuid); }

  void Run() {
    // Start accepting requests to the server.
    completion_queue_ = builder_.AddCompletionQueue();
    server_ = builder_.BuildAndStart();
    HandleRpcs<TMetadata>(completion_queue_.get(), &metadata_map_, *factories_);
  }

 private:
  void DrainQueue(grpc::CompletionQueue* cq) {
    void* tag;
    bool ignored_ok;
    while (cq->Next(&tag, &ignored_ok)) {
      ProceedableWrapper* proceedable_wrapper =
          static_cast<ProceedableWrapper*>(tag);
      proceedable_wrapper->Proceed(Proceedable::OpCode::kShutdown);
    }
  }

  std::unique_ptr<grpc::ServerCompletionQueue> completion_queue_;
  ThreadSafeMap<TMetadata> metadata_map_;
  std::vector<FactoryFunction<TMetadata>>* factories_;
  std::unique_ptr<grpc::Server> server_;
  grpc::ServerBuilder builder_;
};
}  // namespace google::scp::roma::grpc_server

#endif  // ROMA_GRPC_SERVER_NATIVE_FUNCTION_GRPC_SERVER_H_
