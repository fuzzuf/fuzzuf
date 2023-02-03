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

#ifndef FUZZUF_INCLUDE_CLI_FUZZER_AFL_CHECK_PARALLEL_MODE_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_AFL_CHECK_PARALLEL_MODE_ARGS_HPP

#include <boost/program_options.hpp>

namespace fuzzuf::cli {
class GlobalFuzzerOptions;
}

namespace fuzzuf::cli::fuzzer::afl {

class AFLFuzzerOptions;
void CheckParallelModeArgs(const boost::program_options::variables_map &vm,
                           AFLFuzzerOptions &options,
                           GlobalFuzzerOptions &global_options);

}  // namespace fuzzuf::cli::fuzzer::afl

#endif
