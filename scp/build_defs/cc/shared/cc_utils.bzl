# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def cc_utils():
    maybe(
        http_archive,
        name = "nlohmann_json",
        build_file = Label("//scp/build_defs/cc/shared/build_targets:nlohmann.BUILD"),
        sha256 = "e5c7a9f49a16814be27e4ed0ee900ecd0092bfb7dbfca65b5a421b774dccaaed",
        urls = [
            "https://github.com/nlohmann/json/releases/download/v3.11.2/include.zip",
        ],
    )

    maybe(
        http_archive,
        name = "oneTBB",
        # Release 2021.10.0 dated 2023-07-24
        sha256 = "78fb7bb29b415f53de21a68c4fdf97de8ae035090d9ee9caa221e32c6e79567c",
        strip_prefix = "oneTBB-2021.10.0",
        urls = ["https://github.com/oneapi-src/oneTBB/archive/refs/tags/v2021.10.0.zip"],
    )

    maybe(
        http_archive,
        name = "curl",
        build_file = Label("//scp/build_defs/cc/shared/build_targets:curl.BUILD"),
        sha256 = "ff3e80c1ca6a068428726cd7dd19037a47cc538ce58ef61c59587191039b2ca6",
        strip_prefix = "curl-7.49.1",
        urls = [
            "https://mirror.bazel.build/curl.haxx.se/download/curl-7.49.1.tar.gz",
        ],
    )
