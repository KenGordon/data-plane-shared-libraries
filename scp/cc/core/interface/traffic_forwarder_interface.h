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

#ifndef CORE_INTERFACE_TRAFFIC_FORWARDER_INTERFACE_H_
#define CORE_INTERFACE_TRAFFIC_FORWARDER_INTERFACE_H_

#include <string>
#include <string_view>

#include "core/interface/service_interface.h"

namespace google::scp::core {

/**
 * @brief Interface to implement a service that forwards traffic from an
 * address to an address
 */
class TrafficForwarderInterface : public ServiceInterface {
 public:
  virtual ~TrafficForwarderInterface() = default;

  virtual ExecutionResult ResetForwardingAddress(
      std::string_view forwarding_address) noexcept = 0;
};
};  // namespace google::scp::core

#endif  // CORE_INTERFACE_TRAFFIC_FORWARDER_INTERFACE_H_
