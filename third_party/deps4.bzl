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

"""Further initialization of shared control plane dependencies."""

load("@aws_nsm_crate_index//:defs.bzl", nsm_crate_repositories = "crate_repositories")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load(
    "@io_bazel_rules_closure//closure:repositories.bzl",
    "rules_closure_dependencies",
    "rules_closure_toolchains",
)
load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")
load("@io_bazel_rules_docker//repositories:go_repositories.bzl", "go_deps")
load("@rules_buf//gazelle/buf:repositories.bzl", "gazelle_buf_dependencies")

def _aws_nitro_kms_repos():
    nsm_crate_repositories()
    maybe(
        http_archive,
        name = "nitrokmscli_aws_nitro_enclaves_sdk_c",
        build_file = Label("//third_party/aws-nitro-kms:aws_nitro_enclaves_sdk_c.BUILD"),
        patch_args = ["-p1"],
        patches = [Label("//third_party/aws-nitro-kms:aws_nitro_enclaves_sdk_c.patch")],
        sha256 = "87294db0b8001620095f03f560e869a61cae2c64040b34549ff9ae2652cd5cb1",
        strip_prefix = "aws-nitro-enclaves-sdk-c-0.4.1",
        urls = [
            "https://github.com/aws/aws-nitro-enclaves-sdk-c/archive/refs/tags/v0.4.1.zip",
        ],
    )

def deps4():
    container_deps()
    go_deps()
    gazelle_buf_dependencies()
    rules_closure_dependencies()
    rules_closure_toolchains()
    _aws_nitro_kms_repos()
