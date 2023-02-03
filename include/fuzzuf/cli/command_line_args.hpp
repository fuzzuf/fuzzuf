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
#include <string>
#include <vector>

namespace fuzzuf::cli {

// Used only for CLI
// NOTE: A struct dealing with a raw pointer.
//       Beware that the lifetime of this struct must not be longer than that of
//       pointers. This is partly due to using raw pointers while parsing
//       command line options. Maybe we don't have to worry about the lifetime
//       issues when parsing argv originates from main(argc, argv).
struct CommandLineArgs {
  int argc;
  const char** argv;

  std::vector<std::string> Args();
};

}  // namespace fuzzuf::cli
