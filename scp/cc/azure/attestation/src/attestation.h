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

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <string>
#include <fstream>

#include <nlohmann/json.hpp>

namespace google::scp::azure::attestation {

    struct AttestationReport {
        std::string evidence;
        std::string endorsements;
        std::string uvm_endorsements;
        std::string endorsed_tcb;

        operator nlohmann::json() const {
            return nlohmann::json{
                {"evidence", evidence}, 
                {"endorsements", endorsements},
                {"uvm_endorsements", uvm_endorsements},
                {"endorsed_tcb", endorsed_tcb}
            };
        }
    };

    bool hasSnp();
    
    AttestationReport fetchSnpAttestation(const std::string report_data = "");
    
    AttestationReport fetchFakeSnpAttestation();

    std::string getSnpEvidence(const std::string report_data);

    std::string getSnpEndorsements();

    std::string getSnpUvmEndorsements();

    std::string getSnpEndorsedTcb();

} // namespace google::scp::azure::attestation

#endif // ATTESTATION_H
