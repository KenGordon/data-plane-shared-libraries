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
#include <sys/ioctl.h>
#include <sys/types.h>

namespace google::scp::azure::attestation::sev_guest {

  /* linux kernel 6.* versions of the ioctls that talk to the PSP */

  // aka/replaced by this from include/uapi/linux/sev-guest.h
  //
  struct Request {
    uint8_t msg_version; // message version number (must be non-zero)
    uint64_t req_data; // Request and response structure address
    uint64_t resp_data;
    uint64_t fw_err; // firmware error code on failure (see psp-sev.h)
  } snp_guest_request_ioctl;

  constexpr auto IOCTL_TYPE = 'S';
  constexpr auto GET_REPORT = _IOWR(IOCTL_TYPE, 0x0, sizeof(Request));
  constexpr auto GET_DERIVED_KEY = _IOWR(IOCTL_TYPE, 0x1, sizeof(Request));
  constexpr auto GET_EXT_REPORT = _IOWR(IOCTL_TYPE, 0x2, sizeof(Request));

} // namespace google::scp::azure::attestation::sev_guest
