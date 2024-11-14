// Portions Copyright (c) Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "src/azure/attestation/src/attestation.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "src/core/utils/base64.h"

using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;
using google::scp::azure::attestation::SnpReport;

using google::scp::core::utils::Base64Decode;

namespace google::scp::cc::azure::attestation::test {

std::string toHex(const std::string& input) {
  std::stringstream hex_stream;
  for (unsigned char c : input) {
    hex_stream << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(c);
  }
  return hex_stream.str();
}

std::string getReportData(const std::string& snp_evidence_b64) {
  std::string snp_evidence_str;
  Base64Decode(snp_evidence_b64, snp_evidence_str);

  // Parse the byte string into the SnpReport struct
  std::vector<uint8_t> snp_evidence_bytes(snp_evidence_str.begin(),
                                          snp_evidence_str.end());
  SnpReport* snp_report =
      reinterpret_cast<SnpReport*>(snp_evidence_bytes.data());

  // Parse the report data into a string since all tests provided as a string
  std::string report_data_str(
      reinterpret_cast<const char*>(snp_report->report_data),
      sizeof(snp_report->report_data));

  // Remove any trailing zeros as all report data is padded up to 64 bytes
  // Crucially if there is junk memory by accident, this will be left in and
  // tests will fail.
  size_t end = report_data_str.find_last_not_of('\0');
  if (end == std::string::npos) {
    report_data_str.clear();
  } else {
    report_data_str.resize(end + 1);
  }

  std::cout << "report_data: \"" << report_data_str << "\"" << std::endl;
  return report_data_str;
}

class JsonAttestationReportTest : public ::testing::Test {
 protected:
  void SetUp() override {}

  void TearDown() override {}
};

TEST_F(JsonAttestationReportTest, FetchFakeAttestation) {
  EXPECT_TRUE(fetchFakeSnpAttestation().has_value());
}

TEST_F(JsonAttestationReportTest, FetchRealAttestation) {
  if (!hasSnp()) {
    return;
  }
  auto attestation_report = fetchSnpAttestation();
  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence), "");
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationNormalReportData) {
  if (!hasSnp()) {
    return;
  }
  std::string report_data = "example_report_data";
  auto attestation_report = fetchSnpAttestation(toHex(report_data));
  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence), report_data);
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationLongReportData) {
  if (!hasSnp()) {
    return;
  }
  std::string report_data =
      "a_very_long_report_data_string_which_is_so_long_that_it_exceeds_report_"
      "data_length";
  auto attestation_report = fetchSnpAttestation(toHex(report_data));
  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence),
            report_data.substr(0, 64));
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationNonSnp) {
  if (hasSnp()) {
    return;
  }
  EXPECT_FALSE(fetchSnpAttestation().has_value());
}
}  // namespace google::scp::cc::azure::attestation::test
