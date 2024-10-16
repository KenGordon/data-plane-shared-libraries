/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "roma/sandbox/native_function_binding/src/native_function_handler_sapi_ipc.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sys/socket.h>

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "core/test/utils/auto_init_run_stop.h"
#include "public/core/test/interface/execution_result_matchers.h"
#include "roma/sandbox/constants/constants.h"
#include "roma/sandbox/native_function_binding/src/native_function_table.h"
#include "sandboxed_api/sandbox2/comms.h"
#include "scp/cc/roma/sandbox/native_function_binding/src/rpc_wrapper.pb.h"

using google::scp::roma::sandbox::native_function_binding::
    NativeFunctionHandlerSapiIpc;
using google::scp::roma::sandbox::native_function_binding::NativeFunctionTable;
using ::testing::SizeIs;
using ::testing::StrEq;

namespace google::scp::roma::sandbox::native_function_binding::test {
static constexpr char kRequestUuid[] = "foo";

TEST(NativeFunctionHandlerSapiIpcTest, IninRunStop) {
  int fd_pair[2];
  EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_pair), 0);
  std::vector<int> local_fds = {fd_pair[0]};
  std::vector<int> remote_fds = {fd_pair[1]};
  NativeFunctionTable function_table;
  NativeFunctionHandlerSapiIpc handler(&function_table, local_fds, remote_fds);

  EXPECT_SUCCESS(handler.Run());
  EXPECT_SUCCESS(handler.Stop());
}

static bool g_called_registered_function;

void FunctionToBeCalled(FunctionBindingPayload<>& wrapper) {
  g_called_registered_function = true;
  wrapper.io_proto.set_output_string("I'm an output standalone string");
}

TEST(NativeFunctionHandlerSapiIpcTest, ShouldCallFunctionWhenRegistered) {
  int fd_pair[2];
  EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_pair), 0);
  std::vector<int> local_fds = {fd_pair[0]};
  std::vector<int> remote_fds = {fd_pair[1]};
  NativeFunctionTable function_table;
  function_table.Register("cool_function_name", FunctionToBeCalled);
  NativeFunctionHandlerSapiIpc handler(&function_table, local_fds, remote_fds);
  EXPECT_SUCCESS(handler.Run());
  handler.StoreMetadata(kRequestUuid, {});
  g_called_registered_function = false;

  auto remote_fd = remote_fds.at(0);
  sandbox2::Comms comms(remote_fd);
  proto::RpcWrapper rpc_proto;
  rpc_proto.set_function_name("cool_function_name");
  rpc_proto.set_request_uuid(kRequestUuid);
  // Send the request over so that it's handled and the registered function
  // can be called
  EXPECT_TRUE(comms.SendProtoBuf(rpc_proto));
  // Receive the response
  EXPECT_TRUE(comms.RecvProtoBuf(&rpc_proto));

  EXPECT_TRUE(g_called_registered_function);
  EXPECT_THAT(rpc_proto.io_proto().output_string(),
              StrEq("I'm an output standalone string"));
  EXPECT_SUCCESS(handler.Stop());
}

TEST(NativeFunctionHandlerSapiIpcTest,
     ShouldAddErrorsIfFunctionNameIsNotFoundInTable) {
  int fd_pair[2];
  EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_pair), 0);
  std::vector<int> local_fds = {fd_pair[0]};
  std::vector<int> remote_fds = {fd_pair[1]};
  NativeFunctionTable function_table;
  // We don't register any functions with the function table
  NativeFunctionHandlerSapiIpc handler(&function_table, local_fds, remote_fds);
  EXPECT_SUCCESS(handler.Run());
  handler.StoreMetadata(kRequestUuid, {});

  g_called_registered_function = false;

  auto remote_fd = remote_fds.at(0);
  sandbox2::Comms comms(remote_fd);
  proto::RpcWrapper rpc_proto;
  rpc_proto.set_function_name("cool_function_name");
  rpc_proto.set_request_uuid(kRequestUuid);
  // Send the request over so that it's handled and the registered function
  // can be called
  EXPECT_TRUE(comms.SendProtoBuf(rpc_proto));
  // Receive the response
  EXPECT_TRUE(comms.RecvProtoBuf(&rpc_proto));

  EXPECT_FALSE(g_called_registered_function);
  EXPECT_FALSE(rpc_proto.io_proto().has_input_string() ||
               rpc_proto.io_proto().has_input_list_of_string() ||
               rpc_proto.io_proto().has_input_map_of_string());
  EXPECT_GE(rpc_proto.io_proto().errors().size(), 0);
  EXPECT_THAT(rpc_proto.io_proto().errors(0),
              StrEq("ROMA: Failed to execute the C++ function."));
  EXPECT_SUCCESS(handler.Stop());
}

TEST(NativeFunctionHandlerSapiIpcTest,
     ShouldAddErrorsIfFunctionNameIsNotInMetadata) {
  int fd_pair[2];
  EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_pair), 0);
  std::vector<int> local_fds = {fd_pair[0]};
  std::vector<int> remote_fds = {fd_pair[1]};
  NativeFunctionTable function_table;
  // We don't register any functions with the function table
  NativeFunctionHandlerSapiIpc handler(&function_table, local_fds, remote_fds);
  EXPECT_SUCCESS(handler.Run());

  g_called_registered_function = false;

  auto remote_fd = remote_fds.at(0);
  sandbox2::Comms comms(remote_fd);
  proto::RpcWrapper rpc_proto;
  // Send the request over so that it's handled and the registered function
  // can be called
  EXPECT_TRUE(comms.SendProtoBuf(rpc_proto));
  // Receive the response
  EXPECT_TRUE(comms.RecvProtoBuf(&rpc_proto));

  EXPECT_FALSE(g_called_registered_function);
  EXPECT_FALSE(rpc_proto.io_proto().has_input_string() ||
               rpc_proto.io_proto().has_input_list_of_string() ||
               rpc_proto.io_proto().has_input_map_of_string());
  EXPECT_GE(rpc_proto.io_proto().errors().size(), 0);
  EXPECT_THAT(rpc_proto.io_proto().errors(0),
              StrEq("ROMA: Could not find C++ function by name."));
  EXPECT_SUCCESS(handler.Stop());
}

static bool g_called_registered_function_one;
static bool g_called_registered_function_two;

void FunctionOne(FunctionBindingPayload<>& wrapper) {
  g_called_registered_function_one = true;
  wrapper.io_proto.set_output_string("From function one");
}

void FunctionTwo(FunctionBindingPayload<>& wrapper) {
  g_called_registered_function_two = true;
  wrapper.io_proto.set_output_string("From function two");
}

TEST(NativeFunctionHandlerSapiIpcTest, ShouldBeAbleToCallMultipleFunctions) {
  int fd_pair[2];
  EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fd_pair), 0);
  std::vector<int> local_fds = {fd_pair[0]};
  std::vector<int> remote_fds = {fd_pair[1]};
  NativeFunctionTable function_table;
  function_table.Register("cool_function_name_one", FunctionOne);
  function_table.Register("cool_function_name_two", FunctionTwo);
  NativeFunctionHandlerSapiIpc handler(&function_table, local_fds, remote_fds);
  EXPECT_SUCCESS(handler.Run());
  handler.StoreMetadata(kRequestUuid, {});

  g_called_registered_function_one = false;
  g_called_registered_function_two = false;

  auto remote_fd = remote_fds.at(0);
  sandbox2::Comms comms(remote_fd);
  proto::RpcWrapper rpc_proto;
  rpc_proto.set_function_name("cool_function_name_one");
  rpc_proto.set_request_uuid(kRequestUuid);
  // Send the request over so that it's handled and the registered function
  // can be called
  EXPECT_TRUE(comms.SendProtoBuf(rpc_proto));
  // Receive the response
  EXPECT_TRUE(comms.RecvProtoBuf(&rpc_proto));

  EXPECT_TRUE(g_called_registered_function_one);
  EXPECT_EQ(rpc_proto.io_proto().errors().size(), 0);
  EXPECT_THAT(rpc_proto.io_proto().output_string(), StrEq("From function one"));

  rpc_proto.Clear();
  rpc_proto.set_function_name("cool_function_name_two");
  rpc_proto.set_request_uuid(kRequestUuid);
  handler.StoreMetadata(kRequestUuid, {});
  // Send the request over so that it's handled and the registered function
  // can be called
  EXPECT_TRUE(comms.SendProtoBuf(rpc_proto));
  // Receive the response
  EXPECT_TRUE(comms.RecvProtoBuf(&rpc_proto));

  EXPECT_TRUE(g_called_registered_function_two);
  EXPECT_EQ(rpc_proto.io_proto().errors().size(), 0);
  EXPECT_THAT(rpc_proto.io_proto().output_string(), StrEq("From function two"));
  EXPECT_SUCCESS(handler.Stop());
}
}  // namespace google::scp::roma::sandbox::native_function_binding::test
