/*
 * Copyright 2024 Google LLC
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

#include <fstream>
#include <iostream>
#include <string_view>

#include <benchmark/benchmark.h>
#include <nlohmann/json.hpp>

#include "absl/base/log_severity.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/check.h"
#include "absl/log/initialize.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"
#include "src/core/common/uuid/uuid.h"
#include "src/roma/interface/roma.h"
#include "src/roma/roma_service/roma_service.h"
#include "src/roma/tools/v8_cli/utils.h"

namespace {
using google::scp::core::common::ToString;
using google::scp::core::common::Uuid;
using google::scp::roma::CodeObject;
using google::scp::roma::InvocationStrRequest;
using google::scp::roma::ResponseObject;
using google::scp::roma::sandbox::roma_service::RomaService;
using google::scp::roma::tools::v8_cli::ExtractAndSanitizeCustomFlags;

constexpr absl::Duration kRequestTimeout = absl::Seconds(10);
constexpr std::string_view kVersionStr = "v1";
const std::vector<std::string> kBenchmarkFlags = {
    "--udf_file_path",
    "--input_json",
    "--entrypoint",
};
}  // namespace

ABSL_FLAG(std::string, udf_file_path, "", "Path to UDF");
ABSL_FLAG(std::string, input_json, "", "Path to input JSON to UDF");
ABSL_FLAG(std::string, entrypoint, "", "The entrypoint JS function.");

std::unique_ptr<RomaService<>> roma_service;

void LoadCodeObj(std::string_view js) {
  absl::Notification load_finished;

  auto code_obj = std::make_unique<CodeObject>(CodeObject{
      .id = ToString(Uuid::GenerateUuid()),
      .version_string = std::string(kVersionStr),
      .js = std::string(js),
  });
  CHECK_OK(roma_service->LoadCodeObj(std::move(code_obj),
                                     [&](absl::StatusOr<ResponseObject> resp) {
                                       CHECK_OK(resp);
                                       load_finished.Notify();
                                     }));
  load_finished.WaitForNotification();
}

std::vector<std::string> ReadJsonArray(const std::string& filePath) {
  // Read the JSON file into a string
  if (filePath.empty()) {
    return {};
  }

  std::ifstream file(filePath);
  CHECK(file.is_open()) << "Could not open file: " << filePath;

  // Parse the JSON content
  nlohmann::json jsonArray;
  file >> jsonArray;

  // Convert JSON array to std::vector<std::string>
  std::vector<std::string> result;
  for (const auto& element : jsonArray) {
    CHECK(element.is_string()) << "Non-string element found in JSON array";
    result.push_back(absl::StrCat("\"", element.get<std::string>(), "\""));
  }

  return result;
}

void BM_Load(benchmark::State& state) {
  std::ifstream input_str(absl::GetFlag(FLAGS_udf_file_path));
  std::string js((std::istreambuf_iterator<char>(input_str)),
                 (std::istreambuf_iterator<char>()));

  CHECK(!js.empty()) << "Could not open file: "
                     << absl::GetFlag(FLAGS_udf_file_path);

  for (auto _ : state) {
    LoadCodeObj(js);
  }
}

void BM_Execute(benchmark::State& state) {
  std::ifstream input_str(absl::GetFlag(FLAGS_udf_file_path));
  std::string js((std::istreambuf_iterator<char>(input_str)),
                 (std::istreambuf_iterator<char>()));

  CHECK(!js.empty()) << "Could not open file: "
                     << absl::GetFlag(FLAGS_udf_file_path);

  LoadCodeObj(js);
  std::vector<std::string> input =
      ReadJsonArray(absl::GetFlag(FLAGS_input_json));

  for (auto _ : state) {
    absl::Notification execute_finished;

    auto execution_obj =
        std::make_unique<InvocationStrRequest<>>(InvocationStrRequest<>{
            .id = "foo",
            .version_string = std::string(kVersionStr),
            .handler_name = absl::GetFlag(FLAGS_entrypoint),
            .input = input,
        });
    CHECK_OK(roma_service->Execute(std::move(execution_obj),
                                   [&](absl::StatusOr<ResponseObject> resp) {
                                     CHECK_OK(resp);
                                     execute_finished.Notify();
                                   }));

    CHECK(execute_finished.WaitForNotificationWithTimeout(kRequestTimeout));
  }
}

BENCHMARK(BM_Load);
BENCHMARK(BM_Execute);

bool CheckFlag(std::string_view flag_name, std::string_view flag_value,
               std::string_view flag_message) {
  if (flag_value.empty()) {
    std::cerr << "Missing or empty flag --" << flag_name << ": " << flag_message
              << std::endl;
    return false;
  }
  return true;
}

bool FlagsAreValid() {
  bool valid = CheckFlag("udf_file_path", absl::GetFlag(FLAGS_udf_file_path),
                         "Specify the path to the UDF file.") &&
               CheckFlag("entrypoint", absl::GetFlag(FLAGS_entrypoint),
                         "Specify the name of the entrypoint JS function.");
  if (!valid) {
    std::cerr << "\nRoma CLI Benchmarking Tool: " << absl::ProgramUsageMessage()
              << R"(

Usage: src/roma/tools/v8_cli/roma_benchmark --udf_file_path=<path> --input_json=<path> --entrypoint=<function_name>
  --udf_file_path: Path to UDF
  --input_json: Path to input JSON to UDF
  --entrypoint: The entrypoint JS function.
)";
  }
  return valid;
}

int main(int argc, char* argv[]) {
  // Initialize ABSL.
  absl::InitializeLog();
  absl::SetProgramUsageMessage(
      "Opens a shell to support benchmarking UDF code executing within the "
      "Roma V8 execution environment. The google microbenchmarking library is "
      "used, with each load and execute operation independently benchmarked. "
      "All benchmarking flags used with the google microbenchmarking library "
      "are supported.");

  (void)ExtractAndSanitizeCustomFlags(argc, argv, kBenchmarkFlags);

  absl::ParseCommandLine(argc, argv);

  if (!FlagsAreValid()) {
    return 1;
  }

  auto logging_fn = [](absl::LogSeverity severity,
                       const RomaService<>::TMetadata& metadata,
                       std::string_view msg) {
    std::cout << "console: [" << absl::LogSeverityName(severity) << "] " << msg
              << std::endl;
  };
  RomaService<>::Config config;
  config.SetLoggingFunction(std::move(logging_fn));
  config.number_of_workers = 2;

  roma_service.reset(new RomaService<>(std::move(config)));
  CHECK_OK(roma_service->Init());

  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();

  roma_service->Stop().IgnoreError();
  return 0;
}
