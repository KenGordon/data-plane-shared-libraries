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

#include <string>

#include "core/common/uuid/src/uuid.h"

namespace google::scp::core {

using ResourceId = std::string;
using PartitionId = common::Uuid;
using PartitionAddressUri = std::string;

static constexpr char kLocalPartitionAddressUri[] = "";

// Global Partition ID: 00000000-0000-0000-0000-000000000000
static constexpr PartitionId kGlobalPartitionId = {0, 0};

}  // namespace google::scp::core
