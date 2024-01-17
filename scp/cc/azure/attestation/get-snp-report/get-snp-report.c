/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "get-snp-report.h"

bool fetchSnpReport(const char* report_data_hexstring, void** snp_report) {
  bool success = false;
  uint8_t *snp_report_hex;

  if (supportsDevSev()) {
      success = fetchAttestationReport5(report_data_hexstring, (void*) &snp_report_hex);
  } else if (supportsDevSevGuest()) {
      success = fetchAttestationReport6(report_data_hexstring, (void*) &snp_report_hex);
  } else {
      fprintf(stderr, "No supported SNP device found\n");
  }

  if (success) {
      *snp_report = snp_report_hex;
      return 0;
  }

  return -1;
}
