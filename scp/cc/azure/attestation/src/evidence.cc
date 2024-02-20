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

#ifndef ATTESTATION_EVIDENCE_H
#define ATTESTATION_EVIDENCE_H

#include "attestation.h"
#include "sev.h"
#include "sev_guest.h"
#include "core/utils/src/base64.h"

#include <openssl/base64.h>
#include <fcntl.h>

namespace google::scp::azure::attestation {

  std::string base64EncodeBytes(const uint8_t* decoded, size_t size) {
    size_t required_len = 0;
    EVP_EncodedLength(&required_len, size);
    auto buffer = std::make_unique<uint8_t[]>(required_len);
    int ret = EVP_EncodeBlock(buffer.get(), decoded, size);
    return std::string(reinterpret_cast<char*>(buffer.get()), ret);
  }

  SnpReport getSnpEvidenceSev(const std::string report_data) {
  
    SnpRequest request = {};
    std::memcpy(request.report_data, report_data.c_str(), report_data.size());
    SnpResponse response = {};

    sev::Request payload = {
      .req_msg_type = SNP_MSG_REPORT_REQ,
      .rsp_msg_type = SNP_MSG_REPORT_RSP,
      .msg_version = 1,
      .request_len = sizeof(request),
      .request_uaddr = (uint64_t)(void*)&request,
      .response_len = sizeof(response),
      .response_uaddr = (uint64_t)(void*)&response,
      .error = 0
    };

    auto sev_file = open("/dev/sev", O_RDWR | O_CLOEXEC);
    ioctl(sev_file, sev::REQUEST, &payload);
    return response.report;
  }

  SnpReport getSnpEvidenceSevGuest(const std::string report_data) {
  
    SnpRequest request = {};
    std::memcpy(request.report_data, report_data.c_str(), report_data.size());
    SnpResponse response = {};

    sev_guest::Request payload = {
      .msg_version = 1,
      .req_data = (uint64_t)&request,
      .resp_data = (uint64_t)&response,
    };

    auto sev_file = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
    ioctl(sev_file, sev_guest::GET_REPORT, &payload);
    return response.report;
  }
  
  std::string getSnpEvidence(const std::string report_data) {

    SnpReport report;

    switch (getSnpType()) {
      case SnpType::SEV:
        report = getSnpEvidenceSev(report_data);
        break;
      case SnpType::SEV_GUEST:
        report = getSnpEvidenceSevGuest(report_data);
        break;
      default:
        throw std::runtime_error("Unsupported or no SNP type");
    }

    return base64EncodeBytes(reinterpret_cast<const uint8_t*>(&report), sizeof(report));
  }

} // namespace google::scp::azure::attestation

#endif // ATTESTATION_EVIDENCE_H
