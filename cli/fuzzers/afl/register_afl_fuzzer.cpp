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
#include <boost/program_options.hpp>

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"
#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/executor/afl_executor_interface.hpp"

namespace fuzzuf::cli::fuzzer::afl {

// builder_map.insert is called before main function if the below is declared as
// a global variable and linked as an object file. Conversely, if AFL cannot be
// built in a certain environment, do not compile it into an object file to
// prevent AFL from being registered by accident.
static FuzzerBuilderRegister global_afl_register(
    "afl",
    BuildAFLFuzzerFromArgs<fuzzuf::fuzzer::Fuzzer, algorithm::afl::AFLFuzzer,
                           executor::AFLExecutorInterface>);

}  // namespace fuzzuf::cli::fuzzer::afl
