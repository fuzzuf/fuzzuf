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
#include "fuzzuf/cli/fuzzer/aflfast/build_aflfast_fuzzer_from_args.hpp"
#include <iostream>

namespace fuzzuf::algorithm::nezha {
static FuzzerBuilderRegister global_nezha_register(
    "nezha",
    [](FuzzerArgs &args,
       GlobalFuzzerOptions &global_options) -> std::unique_ptr<::Fuzzer> {
      std::unique_ptr<NezhaFuzzer> p(
          new NezhaFuzzer(args, global_options, [](std::string &&m) {
            std::cout << m << std::flush;
          }));
      return p;
    });
}
