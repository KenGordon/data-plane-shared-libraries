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

#ifndef PROXY_SRC_PROXY_SERVER_H_
#define PROXY_SRC_PROXY_SERVER_H_

#include <stdint.h>

#include <boost/asio.hpp>

#include "acceptor_pool.h"
#include "config.h"
#include "socket_types.h"

namespace google::scp::proxy {
class ProxyServer {
 public:
  explicit ProxyServer(const Config& config);

  // Bind and listen on the port.
  void BindListen();
  // Blocking run the proxy. This is intended to be called as a thread.
  void Run(size_t concurrency = 0);

  // Stop the server.
  void Stop();

  uint16_t Port() const { return port_; }

 private:
  void StartAsyncAccept();
  boost::asio::io_context io_context_;
  Acceptor acceptor_;
  // The acceptor pool for handling BIND requests.
  AcceptorPool acceptor_pool_;
  uint16_t port_;
  const bool vsock_;
};
}  // namespace google::scp::proxy

#endif  // PROXY_SRC_PROXY_SERVER_H_
