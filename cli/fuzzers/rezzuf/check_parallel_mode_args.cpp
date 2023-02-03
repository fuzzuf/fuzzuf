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

#include <fuzzuf/cli/fuzzer/rezzuf/build_rezzuf_fuzzer_from_args.hpp>
#include <fuzzuf/utils/check_parallel_mode_args.hpp>

namespace fuzzuf::cli::fuzzer::rezzuf {

void CheckParallelModeArgs(const boost::program_options::variables_map &vm,
                           RezzufFuzzerOptions &options,
                           GlobalFuzzerOptions &global_options) {
  utils::CheckParallelModeArgs(vm, options, global_options);
}

}  // namespace fuzzuf::cli::fuzzer::rezzuf
