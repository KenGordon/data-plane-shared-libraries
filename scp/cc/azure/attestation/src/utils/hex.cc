/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hex.h"

namespace google::scp::azure::attestation::utils {

std::vector<uint8_t> decodeHexString(const std::string_view hexstring, size_t padTo) {
  size_t len = hexstring.length();
  size_t out_len = len / 2;
  if (out_len < padTo) out_len = padTo;

  std::vector<uint8_t> byte_array(out_len, 0); // Initialize with zeros

  for (size_t i = 0; i < len; i += 2) {
    auto hex_digit = hexstring.substr(i, 2);
    uint8_t value = 0;
    // Parse hex_digit into value
    std::from_chars(hex_digit.data(), hex_digit.data() + hex_digit.size(), value, 16);
    byte_array[i / 2] = value;
  }

  return byte_array;
}

} // namespace google::scp::azure::attestation::utils