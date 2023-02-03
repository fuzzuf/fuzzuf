/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
#include "fuzzuf/cli/fuzzer_builder_register.hpp"

#include <utility>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"

namespace fuzzuf::cli {

// A design to prevent an insertion to the map before initialization
// ref. https://stackoverflow.com/a/3746390
BuilderMap& FuzzerBuilderRegister::GetBuilderMap() {
  static BuilderMap builder_map;
  return builder_map;
}

// An API to register each fuzzer's builder before linking
FuzzerBuilderRegister::FuzzerBuilderRegister(std::string name,
                                             FuzzerBuilder builder) {
  GetBuilderMap().insert(std::make_pair(name, builder));
}

FuzzerBuilder FuzzerBuilderRegister::Get(std::string name) {
  auto res = GetBuilderMap().find(name);
  if (res == GetBuilderMap().end()) {
    throw exceptions::cli_error(
        "Failed to get builder of fuzzer \"" + name + "\"", __FILE__, __LINE__);
  }
  DEBUG("[*] Starting fuzzer \"%s\"", name.c_str());
  return res->second;
}

}  // namespace fuzzuf::cli
