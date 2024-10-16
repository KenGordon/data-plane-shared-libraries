#!/bin/bash
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


set -euo pipefail

function calc_sha() {
  declare -r val="$1"
  printf "%s" "${val}" | sha1sum | cut -f1 -d" "
}

declare -r lib="$1"

declare -a -r objdump_args=(
  "--dynamic-syms"
  "--section=.text"
  "${lib}"
)
function objdump_filter() {
    # extract the symbols
    grep -Ewv "SYMBOL TABLE|file format" \
      | grep -o "[^ ]*$" \
      | LC_COLLATE=C sort
}

# shellcheck disable=SC2207
declare -a -r symbols_arr=($(objdump "${objdump_args[@]}" | objdump_filter))
declare -r symbols="${symbols_arr[*]}"
symbols_sha="$(calc_sha "${symbols}")"
readonly symbols_sha

# These are the expected exported symbols. They are essentially all the symbols
# we are overriding. See preload.cc for more details.
declare -a -r expected_symbols_arr=(
  __res_init
  __res_ninit
  accept
  accept4
  bind
  connect
  epoll_ctl
  getsockopt
  ioctl
  listen
  setsockopt
)
declare -r expected_symbols="${expected_symbols_arr[*]}"

expected_sha="$(calc_sha "${expected_symbols}")"
readonly expected_sha

if [[ ${expected_sha} != "${symbols_sha}" ]]; then
  cat << EOF
!! FAILURE !! symbols mismatch
==== Symbols from file ${lib}: ====
${symbols}
sha = ${symbols_sha}
==== Expected Symbols: ====
${expected_symbols}
sha = ${expected_sha}
EOF
  exit 1
fi
