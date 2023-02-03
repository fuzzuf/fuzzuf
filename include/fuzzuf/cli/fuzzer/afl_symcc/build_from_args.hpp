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
#ifndef FUZZUF_INCLUDE_CLI_FUZZER_AFL_SYMCC_BUILD_AFL_SYMCC_FUZZER_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_AFL_SYMCC_BUILD_AFL_SYMCC_FUZZER_FROM_ARGS_HPP
#include <cstddef>
#include <memory>
#include <string>

#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"

namespace fuzzuf::cli::fuzzer::afl_symcc {
struct SymCCOptions {
  std::size_t symcc_freq = 1u;
  std::string target_path;
};

// Used only for CLI
std::unique_ptr<fuzzuf::fuzzer::Fuzzer> BuildFromArgs(
    const FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options);

}  // namespace fuzzuf::cli::fuzzer::afl_symcc

#endif
