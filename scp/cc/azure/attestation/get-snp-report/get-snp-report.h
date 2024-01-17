/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fetch5.h"
#include "fetch6.h"
#include "snp-attestation.h"

bool fetchSnpReport(const char* report_data_hexstring, void** snp_report);