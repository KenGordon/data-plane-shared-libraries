# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Initialize the shared control plane dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//build_defs/cc:sdk_source_code.bzl", scp_sdk_dependencies = "sdk_dependencies")
load("//third_party:emscripten_deps1.bzl", "emscripten_deps1")

def _absl_deps():
    maybe(
        http_archive,
        name = "com_google_absl",
        # commit f845e60 2023-12-05
        sha256 = "b1e113eaf442b817f2a9e3bb471cb36129cd456dd999b0e0360fa891f177013b",
        strip_prefix = "abseil-cpp-f845e60acd880dbf07788a5a2c0dbad0f9c57231",
        urls = ["https://github.com/abseil/abseil-cpp/archive/f845e60acd880dbf07788a5a2c0dbad0f9c57231.zip"],
    )

    # use an older version of absl only for //scp/cc/aws/proxy/src:all. This is
    # to work around the incompatibility between the clang-11 compiler used on
    # amazonlinux2 and the versions of absl since 2023-11-17 (commit 00e087f).
    # clang-11 doesn't have std::filesystem, instead it's in std::experimental
    maybe(
        http_archive,
        name = "com_google_absl_for_proxy",
        sha256 = "497ebdc3a4885d9209b9bd416e8c3f71e7a1fb8af249f6c2a80b7cbeefcd7e21",
        strip_prefix = "abseil-cpp-20230802.1",
        urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230802.1.zip"],
    )

def _rust_deps():
    maybe(
        http_archive,
        name = "rules_rust",
        sha256 = "36ab8f9facae745c9c9c1b33d225623d976e78f2cc3f729b7973d8c20934ab95",
        urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.31.0/rules_rust-v0.31.0.tar.gz"],
    )

def deps1():
    _absl_deps()
    _rust_deps()
    scp_sdk_dependencies()
    emscripten_deps1()
