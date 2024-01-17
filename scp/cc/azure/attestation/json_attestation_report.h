#ifndef JSON_ATTESTATION_REPORT_H
#define JSON_ATTESTATION_REPORT_H

#include "get-snp-report/get-snp-report.h"
#include <nlohmann/json.hpp>
#include "security_context_fetcher.h"

bool hasSnp();
nlohmann::json fetchFakeSnpAttestation();
nlohmann::json fetchSnpAttestation(const std::string report_data = "");

extern "C" {
    bool fetchSnpReport(const char* report_data_hexstring, void* snp_report);
}
#endif // JSON_ATTESTATION_REPORT_H
