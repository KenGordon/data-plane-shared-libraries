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

def import_aws_nitro_enclaves_sdk():
    """
    Import AWS Nitro Enclaves SDK
    """
    maybe(
        http_archive,
        name = "s2n_tls",
        build_file = Label("//build_defs/cc/aws:s2n_tls.BUILD"),
        sha256 = "ce2f531388277de1f65249492b633782c32ba80c3e5b013d067fa44ac7bd1ed1",
        strip_prefix = "s2n-tls-1.3.52",
        urls = [
            "https://github.com/aws/s2n-tls/archive/refs/tags/v1.3.52.zip",
        ],
    )

    maybe(
        http_archive,
        name = "aws_c_sdkutils",
        build_file = Label("//build_defs/cc/aws:aws_c_sdkutils.BUILD"),
        sha256 = "d654670c145212ed3ce0699a988b9f83ebf3e7c44ed74d4d0772dc95ad46b38e",
        strip_prefix = "aws-c-sdkutils-0.1.2",
        urls = [
            "https://github.com/awslabs/aws-c-sdkutils/archive/refs/tags/v0.1.2.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "aws_c_cal",
        build_file = Label("//build_defs/cc/aws:aws_c_cal.BUILD"),
        # Support BoringSSL, committed on May 2, 2023.
        sha256 = "99bbfbfbee523d3ea43e6db08fac83dbb81b215112c55b9731cda9fbe7c4550c",
        strip_prefix = "aws-c-cal-c20ec7e001a8967dbfdbeaf488ccf01afc75c217",
        urls = [
            "https://github.com/awslabs/aws-c-cal/archive/c20ec7e001a8967dbfdbeaf488ccf01afc75c217.zip",
        ],
    )

    maybe(
        http_archive,
        name = "aws_c_io",
        build_file = Label("//build_defs/cc/aws:aws_c_io.BUILD"),
        sha256 = "ce9368ce8cadc09105f26a499767efe575a7a544e8326aa33d0f239309b8bd82",
        strip_prefix = "aws-c-io-0.13.13",
        urls = [
            "https://github.com/awslabs/aws-c-io/archive/refs/tags/v0.13.13.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "aws_c_compression",
        build_file = Label("//build_defs/cc/aws:aws_c_compression.BUILD"),
        sha256 = "8737863ced57d92f5a0bdde554bf0fe70eaa76aae118fec09a6c361dfc55d0d5",
        strip_prefix = "aws-c-compression-0.2.14",
        urls = [
            "https://github.com/awslabs/aws-c-compression/archive/refs/tags/v0.2.14.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "aws_c_http",
        build_file = Label("//build_defs/cc/aws:aws_c_http.BUILD"),
        sha256 = "cde8fbcb52d9c894e75cb398b5c5ea5334188dfc23003c2f7396aa05395f2699",
        strip_prefix = "aws-c-http-0.7.4",
        urls = [
            "https://github.com/awslabs/aws-c-http/archive/refs/tags/v0.7.4.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "aws_c_auth",
        build_file = Label("//build_defs/cc/aws:aws_c_auth.BUILD"),
        sha256 = "691a6b4418afcd3dc141351b6ad33fccd8e3ff84df0e9e045b42295d284ee14c",
        strip_prefix = "aws-c-auth-0.6.22",
        urls = [
            "https://github.com/awslabs/aws-c-auth/archive/refs/tags/v0.6.22.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "json_c",
        build_file = Label("//build_defs/cc/aws:json_c.BUILD"),
        sha256 = "471e9eb1dad4fd2e4fec571d8415993e66a89f23a5b052f1ba11b54db90252de",
        strip_prefix = "json-c-json-c-0.17-20230812",
        urls = [
            "https://github.com/json-c/json-c/archive/refs/tags/json-c-0.17-20230812.zip",
        ],
    )

    maybe(
        http_archive,
        name = "aws-nitro-enclaves-nsm-api",
        build_file = Label("//build_defs/cc/aws:aws_nitro_enclaves_nsm_api.BUILD"),
        sha256 = "8150bb1e9e757f24ff35b19c10b924e2d96ed2a81f98efe05048c50e2e0804e6",
        strip_prefix = "aws-nitro-enclaves-nsm-api-0.4.0",
        urls = ["https://github.com/aws/aws-nitro-enclaves-nsm-api/archive/refs/tags/v0.4.0.zip"],
    )

    maybe(
        http_archive,
        name = "aws_nitro_enclaves_sdk",
        build_file = Label("//build_defs/cc/aws:aws_nitro_enclaves_sdk_source_code.BUILD"),
        patch_args = ["-p1"],
        patches = [Label("//build_defs/cc/aws:aws_nitro_enclaves_sdk.patch")],
        sha256 = "daeb96f0481bfc216d781bcd59605cf2535052ee3c4208efe4045b35e8ae8b65",
        strip_prefix = "aws-nitro-enclaves-sdk-c-0.3.2",
        urls = [
            "https://github.com/aws/aws-nitro-enclaves-sdk-c/archive/refs/tags/v0.3.2.tar.gz",
        ],
    )
