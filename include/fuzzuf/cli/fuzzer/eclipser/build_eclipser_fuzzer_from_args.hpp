/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_CLI_FUZZER_ECLIPSER_BUILD_ECLIPSER_FUZZER_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_ECLIPSER_BUILD_ECLIPSER_FUZZER_FROM_ARGS_HPP

#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"

namespace fuzzuf::cli {

// Used only for CLI
template <class TFuzzer, class TEclipserFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildEclipserFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  std::unique_ptr<TFuzzer> p(
      new TEclipserFuzzer(fuzzer_args, global_options,
                       [](std::string &&m) { std::cout << m << std::flush; }));
  return p;
}

}  // namespace fuzzuf::cli

#endif

