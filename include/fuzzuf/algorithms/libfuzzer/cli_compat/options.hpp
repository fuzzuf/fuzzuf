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
/**
 * @file options.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_OPTIONS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_OPTIONS_HPP

#include <boost/program_options.hpp>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/config.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"

namespace fuzzuf::cli {
struct GlobalFuzzerOptions;
}

namespace fuzzuf::algorithm::libfuzzer {
struct Options {
  int help = 0;
  std::uint32_t exec_timelimit_s = 0u;
  std::uint64_t exec_memlimit_mb = 2048u;
  std::vector<fs::path> targets;
  std::vector<std::string> raw_targets;
  std::vector<std::string> raw_symcc_targets;
  std::vector<std::string> dicts;
  std::vector<std::string> input_dir;
  std::string output_dir;
  std::string exact_output_dir;
  FuzzerCreateInfo create_info;
  unsigned int entropic = 0u;
  signed long long int total_cycles = 0u;
  bool print_final_stats = false;
  std::function<void(std::string &&)> sink;
  std::minstd_rand rng;
};
auto createOptions(Options &)
    -> std::tuple<boost::program_options::options_description,
                  boost::program_options::positional_options_description>;
auto postProcess(
    const boost::program_options::options_description &desc,
    const boost::program_options::positional_options_description &pd, int argc,
    const char *argv[], const cli::GlobalFuzzerOptions &,
    std::function<void(std::string &&)> &&sink, Options &dest) -> bool;
auto loadInitialInputs(Options &dest, std::minstd_rand &rng)
    -> exec_input::ExecInputSet;
}  // namespace fuzzuf::algorithm::libfuzzer

#endif
