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

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/interface/service_interface.h"

namespace google::scp::core {

/// Used internally to store a component registration.
struct ComponentDependencyNode {
  /// The id of the component.
  std::string id;

  /// The ids of the components that this component depends on.
  std::vector<std::string> dependencies;

  /// The factory delegate used to create the component.
  std::function<std::shared_ptr<ServiceInterface>(
      std::map<std::string, std::shared_ptr<ServiceInterface>>)>
      factory;

  bool operator==(const ComponentDependencyNode& otherNode) const {
    return id == otherNode.id;
  }

  bool operator<(const ComponentDependencyNode& otherNode) const {
    return id < otherNode.id;
  }
};

/**
 * @brief Overrides the hash code of the ComponentDependencyNode.
 *
 */
struct NodeHash {
  size_t operator()(const google::scp::core::ComponentDependencyNode& k) const {
    return std::hash<std::string>()(k.id);
  }
};
}  // namespace google::scp::core
