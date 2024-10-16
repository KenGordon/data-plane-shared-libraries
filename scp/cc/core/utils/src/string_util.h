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

#ifndef CORE_UTILS_SRC_STRING_UTIL_H_
#define CORE_UTILS_SRC_STRING_UTIL_H_

#include <list>
#include <string>

namespace google::scp::core::utils {
/**
 * @brief Split a string by a given delimiter string.
 * e.g "one,two,three" -> ["one","two","three"]
 *
 * @param str The input string.
 * @param delimiter The delimiter to split by.
 * @param out The output list containing the split parts.
 */
void SplitStringByDelimiter(std::string_view str, std::string_view delimiter,
                            std::list<std::string>& out);
}  // namespace google::scp::core::utils

#endif  // CORE_UTILS_SRC_STRING_UTIL_H_
