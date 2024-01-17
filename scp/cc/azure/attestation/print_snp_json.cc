#include <iostream>
#include "scp/cc/azure/attestation/json_attestation_report.h"

// Usage: bazel run //scp/cc/azure/attestation:print_snp_json
// The output's path is `bazel-bin/scp/cc/azure/attestation/print_snp_json`.

int main() {
    const bool snp = hasSnp();
    const auto report = hasSnp() ? fetchSnpAttestation() : fetchFakeSnpAttestation();
    std::cout << "report (fake=" << !hasSnp() << "):\n";
    std::cout << report.dump(2) << std::endl;
    return 0;
}