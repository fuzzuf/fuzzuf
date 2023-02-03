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
 * @file config.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CONFIG_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CONFIG_HPP

#include <vector>

#include "fuzzuf/executor/libfuzzer_executor_interface.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/setter.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class EntropicConfig
 * @brief libFuzzer parameters affecting on entropic mode
 */
struct EntropicConfig {
  FUZZUF_SETTER(enabled)
  FUZZUF_SETTER(number_of_rarest_features)
  FUZZUF_SETTER(feature_frequency_threshold)
  FUZZUF_SETTER(scale_per_exec_time)

  /**
   * If true, entropic mode is used to calcurate weight of each corpus elements.
   * Otherwise, traditional "prioritized for new element" rule is used to
   * calcurate energy of each corpus elements.
   */
  bool enabled = false;

  // Following variables are ignored unless entropic mode is enabled.

  /**
   * Max number of features to pay attentions
   * Seldomly detected features are prioritized in entropic mode. If the number
   * of notable features exceeded max size, most frequently detected feature in
   * the notable features is dropped and no longer affect to the energy.
   */
  size_t number_of_rarest_features = 0u;

  /**
   * If the count of the feature detection is higher or equal to this value, the
   * feature is considered as frequently appearing feature and be dropped from
   * notable features.
   */
  size_t feature_frequency_threshold = 0u;

  /**
   * if true, the execution with significantly　different execution time from
   * average causes higher energy. Otherwise, execution time doesn't affect to
   * the energy. Since execution time is not deterministic, this option must not
   * be enabled in unit test codes.
   */
  bool scale_per_exec_time = false;
};

auto toString(std::string &dest, const EntropicConfig &value,
              std::size_t indent_count, const std::string &indent) -> bool;

/**
 * @class Config
 * @brief libFuzzer parameters
 */
struct Config {
  FUZZUF_SETTER(debug)
  FUZZUF_SETTER(entropic)
  FUZZUF_SETTER(reduce_depth)
  FUZZUF_SETTER(use_counters)
  FUZZUF_SETTER(shrink)
  FUZZUF_SETTER(reduce_inputs)
  FUZZUF_SETTER(use_value_profile_mask)
  FUZZUF_SETTER(feature_debug)

  /**
   * if true, debug prints are displayed.
   */
  bool debug = false;

  /**
   * parameters affecting on entropic mode
   */
  EntropicConfig entropic;

  /**
   * Break mutation loop if the mutated input was added to corpus.
   */
  bool reduce_depth = false;

  /**
   * Embed counter at the  lower 8 bit of the feature ID
   * If true, the feature ID of the edge coverage varies for how many times the
   * edge has been executed.
   */
  bool use_counters = false;

  /**
   * Remove execution result that will never be selected from the corpus.
   */
  bool shrink = false;

  /**
   * Prevent adding execution result that has similar result to existing one and
   * longer input
   */
  bool reduce_inputs = false;

  /// not implemented
  bool use_value_profile_mask = false;

  /**
   * Display message when an execution result with shorter input is replacing
   * existing execution result.
   */
  bool feature_debug = false;

  // not implemented
  bool keep_seed = false;
};

auto toString(std::string &dest, const Config &value, std::size_t indent_count,
              const std::string &indent) -> bool;

struct FuzzerCreateInfo {
  FuzzerCreateInfo()
      : input_dir("./input"),
        output_dir("./output"),
        // This is a temporary implementation. Change the implementation
        // properly if the value need to be specified from user side.
        cpu_core_count(fuzzuf::utils::GetCpuCore()),
        cpu_aff(fuzzuf::utils::BindCpu(cpu_core_count, cpuid_to_bind)) {}
  FUZZUF_SETTER(input_dir)
  FUZZUF_SETTER(output_dir)
  FUZZUF_SETTER(dictionaries)
  FUZZUF_SETTER(config)
  FUZZUF_SETTER(mutation_depth)
  FUZZUF_SETTER(max_mutation_retry_count)
  FUZZUF_SETTER(max_mutation_factor)
  FUZZUF_SETTER(do_crossover)
  FUZZUF_SETTER(verbosity)
  // FUZZUF_SETTER( print_new )
  FUZZUF_SETTER(max_mutations_to_print)
  FUZZUF_SETTER(max_unit_size_to_print)
  FUZZUF_SETTER(exec_timelimit_ms)
  FUZZUF_SETTER(exec_memlimit)
  FUZZUF_SETTER(forksrv)
  FUZZUF_SETTER(afl_shm_size)
  FUZZUF_SETTER(bb_shm_size)
  FUZZUF_SETTER(cpuid_to_bind)
  FUZZUF_SETTER(cpu_core_count)
  FUZZUF_SETTER(cpu_aff)
  FUZZUF_SETTER(use_afl_coverage)
  FUZZUF_SETTER(sparse_energy_updates)
  FUZZUF_SETTER(crashed_only)
  FUZZUF_SETTER(max_input_length)
  FUZZUF_SETTER(total_cycles)
  FUZZUF_SETTER(len_control)
  FUZZUF_SETTER(malloc_limit_mb)
  FUZZUF_SETTER(timeout_exitcode)
  FUZZUF_SETTER(error_exit_code)
  FUZZUF_SETTER(max_total_time)
  FUZZUF_SETTER(merge)
  FUZZUF_SETTER(merge_control_file)
  FUZZUF_SETTER(minimize_crash)
  FUZZUF_SETTER(reload)
  FUZZUF_SETTER(jobs)
  FUZZUF_SETTER(workers)
  FUZZUF_SETTER(seed)
  FUZZUF_SETTER(only_ascii)
  FUZZUF_SETTER(print_pcs)
  FUZZUF_SETTER(print_final_stats)
  FUZZUF_SETTER(detect_leaks)
  FUZZUF_SETTER(close_fd_mask)
  FUZZUF_SETTER(crossover_uniform_dist)
  FUZZUF_SETTER(seed_inputs)
  FUZZUF_SETTER(shuffle)
  FUZZUF_SETTER(prefer_small)
  FUZZUF_SETTER(check_input_sha1)

  /**
   * Load initial inputs from this directory
   */
  fs::path input_dir;

  /**
   * Store solutions to this directory
   */
  fs::path output_dir;

  /**
   * Load these dictionaries as manual dict.
   */
  std::vector<fs::path> dictionaries;

  /**
   * Parameters to modify behaviour of libFuzzer
   */
  Config config;

  /**
   * Max mutation retry count
   *
   * Since mutation may fail for exceeding max length, empty dictionary or other
   * reasons, libFuzzer try to retry mutation until the input is actually
   * mutated or retry count exceeds this value.
   */
  unsigned int mutation_depth = 5u;

  /**
   * Max local loop count
   * libFuzzer applies mutate-execute-feedback flow multiple times until new
   * feature is detected or loop count exceeds this value.
   */
  unsigned int max_mutation_retry_count = 20u;

  /**
   * Maximum number of applied mutations for one input value that is not stored
   * in corpus. Note that this value doesn't limit actual local loop count, but
   * just used to detect over mutated input value. Typically, this value need to
   * be equal or higher than max_mutation_retry_count.
   */
  std::uint8_t max_mutation_factor = 20u;

  /**
   * Use crossover mutator
   */
  bool do_crossover = true;

  /**
   * Verbosity of message.
   * 0 : Don't display details.
   * 1 : Display limited range of details.
   * 2 : Display complete details.
   */
  unsigned int verbosity = 1u;

  /**
   * The threshold length of mutation history to display when verbosity == 1
   */
  std::size_t max_mutations_to_print = 10u;

  /**
   * The threshold length of input value to display
   */
  std::size_t max_unit_size_to_print = 0u;

  /**
   * Target that doesn't exit in the following time are terminated and treated
   * as timeout.
   */
  std::uint32_t exec_timelimit_ms = 50u;

  /**
   * Max size of memory the target can use
   */
  std::uint64_t exec_memlimit = 2048ull * 1024ull * 1024ull;

  /**
   * If true, the target is executed using fork server mode.
   * Otherwise, the target is executed using non fork server mode.
   */
  bool forksrv = true;

  /**
   * Size of AFL compatible coverage
   */
  std::uint32_t afl_shm_size = 65536u;

  /**
   * Size of basic block coverage
   */
  std::uint32_t bb_shm_size = 65536u;

  /**
   * cpuid restriction to execute the target
   */
  int cpuid_to_bind = fuzzuf::utils::CPUID_DO_NOT_BIND;

  /**
   * CPU core count
   */
  int cpu_core_count = 0;

  /**
   * Selected CPU core
   */
  int cpu_aff = fuzzuf::utils::CPUID_DO_NOT_BIND;

  /**
   * If true, feature is calculated using AFL compatible coverage
   * Otherwise, feature is calculated using basic block coverage
   */
  bool use_afl_coverage = true;

  /**
   * On entropic mode, even if distribution updating is not required, it is
   * updated with a probability of 1/n.
   */
  std::size_t sparse_energy_updates = 100u;

  /**
   * If true, only crashed execution is recorded to solutions.
   * Otherwise, all execution results added to corupus are recorded to
   * solutions.
   */
  bool crashed_only = true;

  /**
   * Maximum length of the test input.
   * If 0, the appropriate length is automatically selected using initial
   * inputs.
   */
  std::size_t max_input_length = 0u;

  /**
   * Number of individual test runs.
   */
  signed long long total_cycles = -1;

  /**
   * If zero, input value length is constant during fuzzing.
   * Otherwise, input value length starts at 10 and increase for each specified
   * cycles until it exceeds max_input_length
   */
  std::size_t len_control = 100u;

  /// not implemented
  std::size_t malloc_limit_mb = 0u;

  /// not implemented
  int timeout_exitcode = 77;

  /// not implemented
  int error_exit_code = 77;

  /// not implemented
  std::uint64_t max_total_time = 0u;

  /**
   * merge all initial inputs into first input directory
   */
  bool merge = false;

  /// not implemented
  std::string merge_control_file;

  /// not implemented
  std::size_t minimize_crash = 0u;

  /// not implemented
  bool reload = false;

  /// not implemented
  std::size_t jobs = 0u;

  /// not implemented
  std::size_t workers = 0u;

  /// seed value of random number generator
  int seed = 0u;

  /// true: limit mutated input values in range of ASCII character.
  /// false: mutation can produce non ASCII bytes.
  bool only_ascii = false;

  ///　If 1, print out newly covered PCs. Defaults to 0.
  bool print_pcs = false;

  /// If 1, print statistics at exit. Defaults to 0.
  bool print_final_stats = false;

  /// not implemented
  bool detect_leaks = false;

  /// not implemented
  bool close_fd_mask = false;

  /**
   *  true: each corpus elements can be selected as crossover with the same
   * probability false: each corpus elements can be selected as crossover with
   * the distribution used to select seed
   */
  bool crossover_uniform_dist = false;

  /// not implemented
  std::vector<std::string> seed_inputs;

  /**
   * true: shuffle initial inputs before execute them
   * false: execute initial inputs in order
   */
  bool shuffle = true;

  /**
   * true: execute inittial inputs in smallmost to largemost
   * false: execute initial inputs in order
   */
  bool prefer_small = false;

  /**
   * true: ignore input files with diffrent name of sha1 hash of file contents
   * false: accept all input files
   */
  bool check_input_sha1 = false;

  std::size_t target_offset = 0u;
  std::size_t target_count = 0u;
  std::size_t symcc_target_offset = 0u;
  std::size_t symcc_target_count = 0u;

  /**
   * If 0, SymCC is never executed.
   * Otherwise, SymCC is executed if recent n local loop blocks didn't change
   * the corpus.
   */
  unsigned int symcc_freq = 1u;
};

auto toString(std::string &dest, const FuzzerCreateInfo &value,
              std::size_t indent_count, const std::string &indent) -> bool;

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
