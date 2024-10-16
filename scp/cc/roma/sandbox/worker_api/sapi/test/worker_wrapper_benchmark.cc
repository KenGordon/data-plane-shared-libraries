/*
 * Copyright 2023 Google LLC
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

#include <gtest/gtest.h>

#include <benchmark/benchmark.h>

#include "core/interface/errors.h"
#include "public/core/test/interface/execution_result_matchers.h"
#include "roma/config/src/config.h"
#include "roma/logging/src/logging.h"
#include "roma/sandbox/constants/constants.h"
#include "roma/sandbox/worker_api/sapi/src/worker_init_params.pb.h"
#include "roma/sandbox/worker_api/sapi/src/worker_wrapper.h"
#include "sandboxed_api/lenval_core.h"
#include "sandboxed_api/sandbox2/buffer.h"

using google::scp::roma::sandbox::constants::kCodeVersion;
using google::scp::roma::sandbox::constants::kHandlerName;
using google::scp::roma::sandbox::constants::kRequestAction;
using google::scp::roma::sandbox::constants::kRequestActionExecute;
using google::scp::roma::sandbox::constants::kRequestId;
using google::scp::roma::sandbox::constants::kRequestType;
using google::scp::roma::sandbox::constants::kRequestTypeJavascript;
using ::testing::StrEq;

namespace {

constexpr size_t kBufferSize = 1 * 1024 * 1024 /* 1Mib */;

::worker_api::WorkerInitParamsProto GetDefaultInitParams(int fd) {
  ::worker_api::WorkerInitParamsProto init_params;
  init_params.set_require_code_preload_for_execution(false);
  init_params.set_compilation_context_cache_size(5);
  init_params.set_native_js_function_comms_fd(-1);
  init_params.mutable_native_js_function_names()->Clear();
  init_params.set_js_engine_initial_heap_size_mb(0);
  init_params.set_js_engine_maximum_heap_size_mb(0);
  init_params.set_js_engine_max_wasm_memory_number_of_pages(0);
  init_params.set_request_and_response_data_buffer_fd(fd);
  init_params.set_request_and_response_data_buffer_size_bytes(kBufferSize);
  return init_params;
}

::worker_api::WorkerParamsProto GetWorkerParamsProto() {
  ::worker_api::WorkerParamsProto params_proto;
  params_proto.set_code(
      R"js(function cool_func() { return "Hi there from JS :)" })js");
  (*params_proto.mutable_metadata())[kRequestType] = kRequestTypeJavascript;
  (*params_proto.mutable_metadata())[kHandlerName] = "cool_func";
  (*params_proto.mutable_metadata())[kCodeVersion] = "1";
  (*params_proto.mutable_metadata())[kRequestId] = "id";
  (*params_proto.mutable_metadata())[kRequestAction] = kRequestActionExecute;
  return params_proto;
}

void BM_RunCodeFromSerializedData(benchmark::State& state) {
  auto buffer = sandbox2::Buffer::CreateWithSize(kBufferSize);
  ASSERT_TRUE(buffer.ok());
  std::unique_ptr<sandbox2::Buffer> buffer_ptr_ = std::move(buffer).value();

  std::string serialized_init_params;
  ASSERT_TRUE(GetDefaultInitParams(buffer_ptr_->fd())
                  .SerializeToString(&serialized_init_params));

  sapi::LenValStruct sapi_init_params(
      serialized_init_params.size(),
      static_cast<void*>(serialized_init_params.data()));

  ASSERT_EQ(SC_OK, ::InitFromSerializedData(&sapi_init_params));
  ASSERT_EQ(SC_OK, ::Run());

  const ::worker_api::WorkerParamsProto params_proto = GetWorkerParamsProto();
  const int serialized_size = params_proto.ByteSizeLong();

  sapi::LenValStruct sapi_worker_params;

  for (auto _ : state) {
    // The buffer is used for both input and output to the sandbox and so we
    // have to serialize the data into it for each run.
    ASSERT_TRUE(
        params_proto.SerializeToArray(buffer_ptr_->data(), serialized_size));
    size_t output_serialized_size_ptr;
    ASSERT_EQ(SC_OK,
              ::RunCodeFromSerializedData(&sapi_worker_params, serialized_size,
                                          &output_serialized_size_ptr));

    // The rest of the code in this block is to parse and validate the response.
    // We could ignore this and focus the benchmark on just the line above, but
    // that runs the risk of the JS execution failing at some point and not
    // being caught.
    ::worker_api::WorkerParamsProto response_proto;
    ASSERT_TRUE(response_proto.ParseFromArray(buffer_ptr_->data(),
                                              output_serialized_size_ptr));
    EXPECT_THAT(response_proto.response(),
                StrEq(R"js("Hi there from JS :)")js"));
  }
  EXPECT_EQ(SC_OK, ::Stop());
}

void BM_RunCodeFromBuffer(benchmark::State& state) {
  auto buffer = sandbox2::Buffer::CreateWithSize(kBufferSize);
  ASSERT_TRUE(buffer.ok());
  std::unique_ptr<sandbox2::Buffer> buffer_ptr_ = std::move(buffer).value();

  std::string serialized_init_params;
  ASSERT_TRUE(GetDefaultInitParams(buffer_ptr_->fd())
                  .SerializeToString(&serialized_init_params));

  sapi::LenValStruct sapi_init_params(
      serialized_init_params.size(),
      static_cast<void*>(serialized_init_params.data()));

  ASSERT_EQ(SC_OK, ::InitFromSerializedData(&sapi_init_params));
  ASSERT_EQ(SC_OK, ::Run());

  const ::worker_api::WorkerParamsProto params_proto = GetWorkerParamsProto();
  const int serialized_size = params_proto.ByteSizeLong();

  for (auto _ : state) {
    // The buffer is used for both input and output to the sandbox and so we
    // have to serialize the data into it for each run.
    ASSERT_TRUE(
        params_proto.SerializeToArray(buffer_ptr_->data(), serialized_size));
    size_t output_serialized_size_ptr;
    ASSERT_EQ(SC_OK, ::RunCodeFromBuffer(serialized_size,
                                         &output_serialized_size_ptr));

    // The rest of the code in this block is to parse and validate the response.
    // We could ignore this and focus the benchmark on just the line above, but
    // that runs the risk of the JS execution failing at some point and not
    // being caught.
    ::worker_api::WorkerParamsProto response_proto;
    ASSERT_TRUE(response_proto.ParseFromArray(buffer_ptr_->data(),
                                              output_serialized_size_ptr));
    EXPECT_THAT(response_proto.response(),
                StrEq(R"js("Hi there from JS :)")js"));
  }
  EXPECT_EQ(SC_OK, ::Stop());
}

}  // namespace

BENCHMARK(BM_RunCodeFromSerializedData);
BENCHMARK(BM_RunCodeFromBuffer);

// Run the benchmark
BENCHMARK_MAIN();
