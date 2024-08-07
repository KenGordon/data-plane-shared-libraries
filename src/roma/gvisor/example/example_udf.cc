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

#include <iostream>

#include "src/roma/gvisor/example/example.pb.h"

using ::privacy_sandbox::server_common::gvisor::example::EchoRequest;
using ::privacy_sandbox::server_common::gvisor::example::EchoResponse;

int main(int argc, char* argv[]) {
  EchoRequest request;
  // Any initialization work can be done before this point.
  // The following line will result in a blocking read being performed by the
  // binary i.e. waiting for input before execution.
  // The EchoRequest proto is defined by the Trusted Server team. The UDF reads
  // request from stdin.
  request.ParseFromIstream(&std::cin);

  EchoResponse response;
  response.set_message(request.message());

  // Once the UDF is done executing, it should write the response (EchoResponse
  // in this case) to the stdout.
  response.SerializeToOstream(&std::cout);
  return 0;
}
