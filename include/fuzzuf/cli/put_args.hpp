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
#include "fuzzuf/cli/command_line_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::cli {

struct PutArgs {
  std::vector<std::string> args;
  int argc;

  PutArgs(std::vector<std::string> args) : args(args), argc(args.size()) {}

  void Check() {
    if (args.size() == 0) {
      throw exceptions::cli_error(
          fuzzuf::utils::StrPrintf("Command line of PUT is not specified"),
          __FILE__, __LINE__);
    }
  }

  std::vector<std::string>& Args() { return this->args; }
};

}  // namespace fuzzuf::cli
