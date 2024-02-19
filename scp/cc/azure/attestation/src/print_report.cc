/*
 * Portions Copyright (c) Microsoft Corporation
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

#include <iostream>
#include <nlohmann/json.hpp>

#include "scp/cc/azure/attestation/src/report.h"

using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;

namespace google::scp::cc::azure::attestation {

  int main() {
    const auto attestation_report =
        hasSnp() ? fetchSnpAttestation() : fetchFakeSnpAttestation();
    std::cout << "report (fake=" << !hasSnp() << "):\n";
    nlohmann::json json_report = attestation_report;
    std::cout << json_report.dump(2) << std::endl;
    return 0;
  }

}  // namespace google::scp::cc::azure::attestation

