// Copyright 2022 Google LLC
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

#include "proxy/src/socket_vendor_server.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "proxy/src/socket_types.h"

namespace {

using google::scp::proxy::Endpoint;
using google::scp::proxy::SocketVendorServer;

TEST(SocketVendorServerTest, EmptyPath) {
  Endpoint proxy_endpoint;
  SocketVendorServer server(/*sock_path=*/"", proxy_endpoint,
                            /*concurrency=*/1);
  EXPECT_FALSE(server.Init());
}

TEST(SocketVendorServerTest, NonExistentFile) {
  Endpoint proxy_endpoint;
  SocketVendorServer server(/*sock_path=*/"/foo/bar", proxy_endpoint,
                            /*concurrency=*/1);
  EXPECT_FALSE(server.Init());
}

TEST(SocketVendorServerTest, InitSuccess) {
  const std::filesystem::path temp_file_path =
      std::filesystem::temp_directory_path() / "sock_path";
  // Write to the file so that it exists:
  std::ofstream ofstream(temp_file_path);
  ofstream << "";
  ofstream.close();

  Endpoint proxy_endpoint;
  SocketVendorServer server(/*sock_path=*/std::string(temp_file_path),
                            proxy_endpoint,
                            /*concurrency=*/1);
  EXPECT_TRUE(server.Init());
}

TEST(SocketVendorServerTest, RunStop) {
  const std::filesystem::path temp_file_path =
      std::filesystem::temp_directory_path() / "sock_path";
  // Write to the file so that it exists:
  std::ofstream ofstream(temp_file_path);
  ofstream << "";
  ofstream.close();

  Endpoint proxy_endpoint;
  SocketVendorServer server(/*sock_path=*/std::string(temp_file_path),
                            proxy_endpoint,
                            /*concurrency=*/1);
  ASSERT_TRUE(server.Init());
  std::thread server_thread([&server] { server.Run(); });
  server.Stop();
  server_thread.join();
}

}  // namespace
