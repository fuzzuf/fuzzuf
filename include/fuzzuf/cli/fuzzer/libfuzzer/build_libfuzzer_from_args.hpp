/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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

#include "fuzzuf/cli/fuzzer_builder_register.hpp"
#include "fuzzuf/cli/fuzzer/libfuzzer/build_libfuzzer_from_args.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include <boost/program_options.hpp>

namespace po = boost::program_options;

// Used only for CLI
template <class TFuzzer, class TLibFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildLibFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, 
    GlobalFuzzerOptions &global_options
) {
    std::unique_ptr<TFuzzer> p(
        new TLibFuzzer(fuzzer_args, global_options,
                    [](std::string &&m) { std::cout << m << std::flush; }));
    return p;
}
