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
#pragma once

#include <map>

#include "fuzzuf/cli/fuzzer_builder.hpp"

namespace fuzzuf::cli {

using BuilderMap = std::map<std::string, FuzzerBuilder>;

// Used only for CLI
class FuzzerBuilderRegister {
 public:
  FuzzerBuilderRegister(std::string name, FuzzerBuilder builder);

  static FuzzerBuilder Get(std::string name);

 private:
  static BuilderMap& GetBuilderMap();
};

}  // namespace fuzzuf::cli
