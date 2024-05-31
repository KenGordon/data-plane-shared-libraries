// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <unistd.h>

#include <cmath>
#include <cstring>
#include <iostream>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "src/roma/gvisor/udf/roma_binary.pb.h"

using privacy_sandbox::server_common::gvisor::BinaryRequest;
using privacy_sandbox::server_common::gvisor::BinaryResponse;

// Find all prime numbers less than this:
constexpr int kPrimeCount = 100'000;

void RunHelloWorld(BinaryResponse& bin_response) {
  bin_response.set_greeting("Hello, world!");
}

void RunPrimeSieve(BinaryResponse& bin_response) {
  // Create a boolean array of size n+1
  std::vector<bool> primes(kPrimeCount + 1, true);
  // Set first two values to false
  primes[0] = false;
  primes[1] = false;
  // Loop through the elements
  for (int i = 2; i <= sqrt(kPrimeCount); i++) {
    if (primes[i]) {
      for (int j = i * i; j <= kPrimeCount; j += i) {
        primes[j] = false;
      }
    }
  }
  // Loop through the array from 2 to n
  for (int i = 2; i <= kPrimeCount; i++) {
    if (primes[i]) {
      bin_response.add_prime_number(i);
    }
  }
}

int main(int argc, char* argv[]) {
  absl::InitializeLog();
  if (argc < 2) {
    LOG(ERROR) << "Not enough arguments!";
    return -1;
  }

  BinaryRequest bin_request;
  bin_request.ParseFromFileDescriptor(STDIN_FILENO);
  int32_t write_fd;
  CHECK(absl::SimpleAtoi(argv[1], &write_fd))
      << "Conversion of write file descriptor string to int failed";
  BinaryResponse bin_response;
  switch (bin_request.function()) {
    case BinaryRequest::FUNCTION_HELLO_WORLD:
      RunHelloWorld(bin_response);
      break;
    case BinaryRequest::FUNCTION_PRIME_SIEVE:
      RunPrimeSieve(bin_response);
      break;
    default:
      abort();
  }

  bin_response.SerializeToFileDescriptor(write_fd);
  close(write_fd);
  return 0;
}
