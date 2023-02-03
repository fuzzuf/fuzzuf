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
#include "fuzzuf/algorithms/libfuzzer/cli_compat/fuzzer.hpp"
#include "fuzzuf/cli/fuzzer/libfuzzer/build_libfuzzer_from_args.hpp"
#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/executor/libfuzzer_executor_interface.hpp"

namespace fuzzuf::algorithm::libfuzzer {
static cli::FuzzerBuilderRegister global_libfuzzer_register(
    "libfuzzer",
    cli::BuildLibFuzzerFromArgs<fuzzer::Fuzzer, algorithm::libfuzzer::LibFuzzer,
                                executor::LibFuzzerExecutorInterface>);
}
