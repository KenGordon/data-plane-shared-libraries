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

#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>

namespace google::scp::azure::attestation::sev {

  /* linux kernel 5.15.* versions of the ioctls that talk to the PSP */

  /* From sev-snp driver include/uapi/linux/psp-sev-guest.h */
  struct Request {
    uint8_t req_msg_type;
    uint8_t rsp_msg_type;
    uint8_t msg_version;
    uint16_t request_len;
    uint64_t request_uaddr;
    uint16_t response_len;
    uint64_t response_uaddr;
    uint32_t error; /* firmware error code on failure (see psp-sev.h) */
  };

  constexpr auto IOCTL_TYPE = 'S';
  constexpr auto REQUEST = _IOWR(IOCTL_TYPE, 0x0, sizeof(Request));
  constexpr auto REPORT = _IOWR(IOCTL_TYPE, 0x1, sizeof(Request));
  constexpr auto KEY = _IOWR(IOCTL_TYPE, 0x2, sizeof(Request));

  SnpReport getReport(const std::string report_data) {
  
    SnpRequest request = {};
    std::memcpy(request.report_data, report_data.c_str(), report_data.size());
    SnpResponse response = {};

    Request payload = {
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
    auto rc = ioctl(sev_file, REQUEST, &payload);
    return response.report;
  }

}  // namespace google::scp::azure::attestation::sev
