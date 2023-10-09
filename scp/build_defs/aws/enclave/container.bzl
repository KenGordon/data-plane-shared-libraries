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

load("@io_bazel_rules_docker//container:container.bzl", "container_image")

# Note: use reproducible versions of these binaries.
_PROXY_BINARY_FILES = [Label("//scp/cc/aws/proxy:libproxy_preload.so"), Label("//scp/cc/aws/proxy:proxify"), Label("//scp/cc/aws/proxy:socket_vendor")]

def java_enclave_image(
        *,
        name,
        jar_target,
        jar_filename,
        additional_files = [],
        additional_tars = [],
        enclave_cmd_override = [],
        enclave_env_variables = {},
        jar_args = [],
        jvm_options = [],
        repo_name = ""):
    """Creates a target for a Docker container with the necessary files for
    doing attested decryptions and communicating over the proxy. Exposes
    ${name}.tar

    Args:
      name: Name used for the generated container_image
      jar_target: Bazel target to include in the container
        (e.g. //java:foo_deploy.jar)
      jar_filename: Filename of the jar file generated by jar_target prefixed
        with "/" (e.g. "/foo_deploy.jar")" -- provided manually because there
        doesn't seem to be a straightforward way of getting the resulting
        filename from the target in a bazel macro.
      additional_files: Additional files to include in the container root.
      additional_tars: Additional files include in the container based on their
        paths within the tar.
      enclave_cmd_override: "cmd" parameter to use with the container_image
        instead of the default `java -jar <binary> <jar_args>` Only used for
        testing purposes -- if empty, the default value will be used.
      enclave_env_variables: Dict (string-to-string) of environment variables to
        be added to the enclave.
      jar_args: CLI args passed to the JAR file inside the enclave.
      jvm_options: Jvm options passed to control jvm inside the enclave.
      repo_name: Deprecated, left for compatibility purposes but unused and ignored.
    """

    container_files = [
        jar_target,
        "@kmstool_enclave_cli//file",
    ] + additional_files

    container_tars = [
        Label("//operator/worker/aws:libnsm-tar"),
    ] + additional_tars

    for b in _PROXY_BINARY_FILES:
        container_files.append(b)

    enclave_cmd = ["/proxify", "/usr/bin/java"] + jvm_options + \
                  ["-jar", jar_filename] + jar_args

    if len(enclave_cmd_override) > 0:
        enclave_cmd = enclave_cmd_override

    container_image(
        name = name,
        base = "@java_base//image",
        cmd = enclave_cmd,
        env = enclave_env_variables,
        files = container_files,
        tars = container_tars,
    )
