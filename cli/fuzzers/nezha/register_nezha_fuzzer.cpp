/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#include "fuzzuf/algorithms/nezha/cli_compat/fuzzer.hpp"
#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/cli/fuzzer/nezha/build_nezha_fuzzer_from_args.hpp"
#include "fuzzuf/executor/libfuzzer_executor_interface.hpp"
#include <iostream>

namespace fuzzuf::algorithm::nezha {
  static FuzzerBuilderRegister global_nezha_register("nezha", BuildNezhaFuzzerFromArgs<Fuzzer, fuzzuf::algorithm::nezha::NezhaFuzzer, executor::LibFuzzerExecutorInterface>);
}

