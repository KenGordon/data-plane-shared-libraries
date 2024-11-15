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

#include "src/azure/attestation/src/sev6.h"
#include "src/core/utils/base64.h"

using google::scp::azure::attestation::AttestationReport;
using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;
using google::scp::azure::attestation::SnpReport;
using google::scp::azure::attestation::sev6::getReport;

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

std::array<uint8_t, 64> getReportData(const std::string& snp_evidence_b64) {
  std::string snp_evidence_str;
  Base64Decode(snp_evidence_b64, snp_evidence_str);

  // Parse the byte string into the SnpReport struct
  std::vector<uint8_t> snp_evidence_bytes(snp_evidence_str.begin(),
                                          snp_evidence_str.end());
  SnpReport snp_report;
  EXPECT_EQ(snp_evidence_bytes.size(), sizeof(SnpReport));
  std::memcpy(&snp_report, snp_evidence_bytes.data(), sizeof(SnpReport));

  std::array<uint8_t, 64> report_data;
  EXPECT_EQ(sizeof(snp_report.report_data), report_data.size());
  std::memcpy(&report_data, snp_report.report_data, report_data.size());
  return report_data;
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
  // Define test inputs and outputs
  // Input is omitted as we're testing default is ""
  std::array<uint8_t, 64> expected = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };

  std::optional<AttestationReport> attestation_report = fetchSnpAttestation();

  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence), expected);
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationNormalReportData) {
  if (!hasSnp()) {
    return;
  }
  // Define test inputs and outputs
  std::string report_data = toHex("example_report_data");
  std::array<uint8_t, 64> expected = {
      'e', 'x', 'a', 'm', 'p', 'l', 'e', '_', 'r', 'e', 'p', 'o', 'r',
      't', '_', 'd', 'a', 't', 'a', 0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  };

  std::optional<AttestationReport> attestation_report =
      fetchSnpAttestation(report_data);

  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence), expected);
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationReportDataWithNull) {
  if (!hasSnp()) {
    return;
  }
  // Define test inputs and outputs
  std::string report_data =
      "6578616d706c655f776974685f005f63686172";  // "example_with_\0_char"
  std::array<uint8_t, 64> expected = {
      'e', 'x', 'a', 'm', 'p', 'l', 'e', '_', 'w', 'i', 't', 'h', '_',
      0,   '_', 'c', 'h', 'a', 'r', 0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  };

  std::optional<AttestationReport> attestation_report =
      fetchSnpAttestation(report_data);

  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence), expected);
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationLongReportData) {
  if (!hasSnp()) {
    return;
  }
  // Define test inputs and outputs
  std::string report_data = toHex(
      "a_very_long_report_data_string_which_is_so_long_that_it_exceeds_report_"
      "data_length");
  std::array<uint8_t, 64> expected = {
      'a', '_', 'v', 'e', 'r', 'y', '_', 'l', 'o', 'n', 'g', '_', 'r',
      'e', 'p', 'o', 'r', 't', '_', 'd', 'a', 't', 'a', '_', 's', 't',
      'r', 'i', 'n', 'g', '_', 'w', 'h', 'i', 'c', 'h', '_', 'i', 's',
      '_', 's', 'o', '_', 'l', 'o', 'n', 'g', '_', 't', 'h', 'a', 't',
      '_', 'i', 't', '_', 'e', 'x', 'c', 'e', 'e', 'd', 's', '_',
  };

  std::optional<AttestationReport> attestation_report =
      fetchSnpAttestation(report_data);

  EXPECT_TRUE(attestation_report.has_value());
  EXPECT_EQ(getReportData(attestation_report->evidence), expected);
}

TEST_F(JsonAttestationReportTest, FetchRealAttestationNonSnp) {
  if (hasSnp()) {
    return;
  }
  EXPECT_FALSE(fetchSnpAttestation().has_value());
}

TEST_F(JsonAttestationReportTest, GetReport) {
  if (!hasSnp()) {
    return;
  }
  // Define test inputs and outputs
  std::string report_data = "";
  uint8_t expected[64] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };

  std::unique_ptr<SnpReport> snp_report = getReport(report_data);

  EXPECT_TRUE(std::equal(std::begin(expected), std::end(expected),
                         std::begin(snp_report.get()->report_data)));
}

TEST_F(JsonAttestationReportTest, GetReportWithReportDataUnder64) {
  if (!hasSnp()) {
    return;
  }
  // Define test inputs and outputs
  std::string report_data = toHex("example_report_data");
  uint8_t expected[64] = {
      'e', 'x', 'a', 'm', 'p', 'l', 'e', '_', 'r', 'e', 'p', 'o', 'r',
      't', '_', 'd', 'a', 't', 'a', 0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  };

  std::unique_ptr<SnpReport> snp_report = getReport(report_data);

  EXPECT_TRUE(std::equal(std::begin(expected), std::end(expected),
                         std::begin(snp_report.get()->report_data)));
}

TEST_F(JsonAttestationReportTest, GetReportWithReportDataOver64) {
  if (!hasSnp()) {
    return;
  }
  // Define test inputs and outputs
  std::string report_data = toHex(
      "a_very_long_report_data_string_which_is_so_long_that_it_exceeds_report_"
      "data_length");
  uint8_t expected[64] = {
      'a', '_', 'v', 'e', 'r', 'y', '_', 'l', 'o', 'n', 'g', '_', 'r',
      'e', 'p', 'o', 'r', 't', '_', 'd', 'a', 't', 'a', '_', 's', 't',
      'r', 'i', 'n', 'g', '_', 'w', 'h', 'i', 'c', 'h', '_', 'i', 's',
      '_', 's', 'o', '_', 'l', 'o', 'n', 'g', '_', 't', 'h', 'a', 't',
      '_', 'i', 't', '_', 'e', 'x', 'c', 'e', 'e', 'd', 's', '_',
  };

  std::unique_ptr<SnpReport> snp_report = getReport(report_data);

  EXPECT_TRUE(std::equal(std::begin(expected), std::end(expected),
                         std::begin(snp_report.get()->report_data)));
}
}  // namespace google::scp::cc::azure::attestation::test
