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
 * @file config.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/config.hpp"

#include "fuzzuf/algorithms/libfuzzer/utils.hpp"

namespace fuzzuf::algorithm::libfuzzer {

auto toString(std::string &dest, const EntropicConfig &value,
              std::size_t indent_count, const std::string &indent) -> bool {
  utils::make_indent(dest, indent_count, indent);
  dest += "EntropicConfig\n";
  ++indent_count;
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(enabled)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(number_of_rarest_features)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(feature_frequency_threshold)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(scale_per_exec_time)
  return true;
}

auto toString(std::string &dest, const Config &value, std::size_t indent_count,
              const std::string &indent) -> bool {
  utils::make_indent(dest, indent_count, indent);
  dest += "Config\n";
  ++indent_count;
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(debug)
  toString(dest, value.entropic, indent_count, indent);
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(reduce_depth)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(use_counters)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(shrink)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(reduce_inputs)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(use_value_profile_mask)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(feature_debug)
  return true;
}

auto toString(std::string &dest, const FuzzerCreateInfo &value,
              std::size_t indent_count, const std::string &indent) -> bool {
  utils::make_indent(dest, indent_count, indent);
  dest += "FuzzerCreateInfo\n";
  ++indent_count;
  toString(dest, value.config, indent_count, indent);
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(mutation_depth)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(max_mutation_retry_count)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(max_mutation_factor)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(do_crossover)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(verbosity)
  // FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER( print_new )
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(max_mutations_to_print)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(max_unit_size_to_print)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(exec_timelimit_ms)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(exec_memlimit)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(forksrv)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(afl_shm_size)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(bb_shm_size)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(cpuid_to_bind)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(use_afl_coverage)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(sparse_energy_updates)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(crashed_only)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(max_input_length)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(total_cycles)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(len_control)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(malloc_limit_mb)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(timeout_exitcode)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(error_exit_code)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(max_total_time)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(merge)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(merge_control_file)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(minimize_crash)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(reload)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(jobs)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(workers)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(seed)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(only_ascii)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(print_pcs)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(print_final_stats)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(detect_leaks)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(close_fd_mask)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(crossover_uniform_dist)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(seed_inputs)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(shuffle)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(prefer_small)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(check_input_sha1)
  return true;
}

}  // namespace fuzzuf::algorithm::libfuzzer
