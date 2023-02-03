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
 * @file options.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/cli_compat/options.hpp"

#include <boost/program_options.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "fuzzuf/algorithms/libfuzzer/calc_max_length.hpp"
#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_initial_exec_input_set.hpp"
#include "fuzzuf/algorithms/libfuzzer/exec_input_set_range.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/utils/load_inputs.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::libfuzzer {
auto createOptions(Options &dest)
    -> std::tuple<boost::program_options::options_description,
                  boost::program_options::positional_options_description> {
  namespace po = boost::program_options;
  po::options_description desc("Options");
  desc.add_options()(
      "target",
      po::value<std::vector<std::string>>(&dest.raw_targets)->multitoken(),
      "Mandatory option. Path to the target executable.")(
      "symcc_target",
      po::value<std::vector<std::string>>(&dest.raw_symcc_targets)
          ->multitoken(),
      "Path to the target executable compiled by SymCC.")(
      "symcc_freq", po::value<unsigned int>(&dest.create_info.symcc_freq),
      "SymCC execution frequency."
      "If 0, SymCC is never executed."
      "Otherwise, SymCC is executed if recent n local loop blocks didn't "
      "change the corpus."
      "Default 1.")(
      "input",
      po::value<std::vector<std::string>>(&dest.input_dir)->multitoken(),
      "Provide a dictionary of input keywords; see Dictionaries."
      "(Note: fuzzuf's implementation loads input from directory. Each files "
      "in the directory contains one input.)")(
      "verbosity", po::value<unsigned int>(&dest.create_info.verbosity),
      "Verbosity level, default 1.")("entropic",
                                     po::value<unsigned int>(&dest.entropic),
                                     "Use entropic mode, default 0.")(
      "reduce_depth", po::value<bool>(&dest.create_info.config.reduce_depth),
      "Experimental/internal. "
      "Reduce depth if mutations lose unique features. Default to 0.")(
      "shrink", po::value<bool>(&dest.create_info.config.shrink),
      "Replace values on corpus by shorter input with same coverage, default "
      "0.")("seed", po::value<int>(&dest.create_info.seed),
            "Random seed. If 0, seed is generated. Default to 0.")(
      "runs", po::value<signed long long>(&dest.total_cycles),
      "Number of individual test runs (-1 for infinite runs).")(
      "max_len", po::value<std::size_t>(&dest.create_info.max_input_length),
      "Maximum length of the test input. "
      "If 0, libFuzzer tries to guess a good value based on the corpus "
      "and reports it. Default to 0.")(
      "len_control", po::value<std::size_t>(&dest.create_info.len_control),
      "Try generating small inputs first, "
      "then try larger inputs over time.  Specifies the rate at which the "
      "length "
      "limit is increased (smaller == faster).  If 0, immediately try inputs "
      "with "
      "size up to max_len. Default value is 0, if LLVMFuzzerCustomMutator is "
      "used.")("timeout", po::value<std::uint32_t>(&dest.exec_timelimit_s),
               "Timeout in seconds (if positive). "
               "If one unit runs more than this number of seconds the process "
               "will abort. Default to 50 milliseconds.")(
      "rss_limit_mb", po::value<std::uint64_t>(&dest.exec_memlimit_mb),
      "If non-zero, the fuzzer will exit upon"
      "reaching this limit of RSS memory usage.")(
      "malloc_limit_mb, Default to 2GiB.",
      po::value<std::size_t>(&dest.create_info.malloc_limit_mb),
      "If non-zero, the fuzzer will exit "
      "if the target tries to allocate this number of Mb with one malloc call. "
      "If zero (default) same limit as rss_limit_mb is applied. Default to 0."
      "(not implemented yet)")(
      "timeout_exitcode", po::value<int>(&dest.create_info.timeout_exitcode),
      "When libFuzzer reports a timeout "
      "this exit code will be used. Default to 77."
      "(not implemented yet)")(
      "error_exitcode", po::value<int>(&dest.create_info.error_exit_code),
      "When libFuzzer itself reports a bug "
      "this exit code will be used. Default to 77."
      "(not implemented yet)")(
      "max_total_time",
      po::value<std::uint64_t>(&dest.create_info.max_total_time),
      "If positive, indicates the maximal total "
      "time in seconds to run the fuzzer. Default to 0."
      "(not implemented yet)")(
      "merge", po::value<bool>(&dest.create_info.merge),
      "If 1, the 2-nd, 3-rd, etc corpora will be "
      "merged into the 1-st corpus. Only interesting units will be taken. "
      "This flag can be used to minimize a corpus. Default to 0.")(
      "merge_control_file",
      po::value<std::string>(&dest.create_info.merge_control_file),
      "Specify a control file used for the merge process. "
      "If a merge process gets killed it tries to leave this file "
      "in a state suitable for resuming the merge. "
      "By default a temporary file will be used."
      "The same file can be used for multistep merge process."
      "(not implemented yet)")(
      "minimize_crash",
      po::value<std::size_t>(&dest.create_info.minimize_crash),
      "If 1, minimizes the provided"
      " crash input. Use with -runs=N or -max_total_time=N to limit "
      "the number attempts."
      " Use with -exact_artifact_path to specify the output."
      " Combine with ASAN_OPTIONS=dedup_token_length=3 (or similar) to ensure "
      "that"
      " the minimized input triggers the same crash. Default to 0."
      "(not implemented yet)")(
      "reload", po::value<bool>(&dest.create_info.reload),
      "Reload the main corpus every <N> seconds to get new units"
      " discovered by other processes. If 0, disabled. Default to 0."
      "(not implemented yet)")(
      "jobs", po::value<std::size_t>(&dest.create_info.jobs),
      "Number of jobs to run. If jobs >= 1 we spawn"
      " this number of jobs in separate worker processes"
      " with stdout/stderr redirected to fuzz-JOB.log. Default to 0"
      "(not implemented yet)")(
      "workers", po::value<std::size_t>(&dest.create_info.workers),
      "Number of simultaneous worker processes to run the jobs."
      " If zero, \"min(jobs,NumberOfCpuCores()/2)\" is used. Default to 0."
      "(not implemented yet)")(
      "dict", po::value<std::vector<std::string>>(&dest.dicts)->multitoken(),
      "Experimental. Use the dictionary file. Default to no dictionaries.")(
      "use_counters", po::value<bool>(&dest.create_info.config.use_counters),
      "If non-zero, use coverage counters. Default to 0.")(
      "reduce_inputs", po::value<bool>(&dest.create_info.config.reduce_inputs),
      "If non-zero, try to reduce the size of inputs while preserving their "
      "full feature "
      "sets. Default to 0.")(
      "use_value_profile",
      po::value<bool>(&dest.create_info.config.use_value_profile_mask),
      "Experimental. If non-zero, use value profile to guide fuzzing. Default "
      "to 0."
      "(not implemented yet)")(
      "only_ascii", po::value<bool>(&dest.create_info.only_ascii),
      "If 1, generate only ASCII (isprint+isspace) inputs. Default to 0.")(
      "artifact_prefix", po::value<std::string>(&dest.output_dir),
      "Write fuzzing artifacts (crash, "
      "timeout, or slow inputs) as "
      "$(artifact_prefix)file."
      "(Note: fuzzuf's implementation stores artifacts into the directory. "
      "Default is /tmp/fuzzuf-out_dir/."
      "Each outputs are stored in different files in the directory.)")(
      "exact_artifact_path", po::value<std::string>(&dest.exact_output_dir),
      "Write the single artifact on failure (crash, timeout) "
      "as $(exact_artifact_path). This overrides -artifact_prefix "
      "and will not use checksum in the file name. Do not "
      "use the same path for several parallel processes."
      "(Note: fuzzuf's implementation stores artifacts into the directory. "
      "Each outputs are stored in different files in the directory.)")(
      "print_pcs", po::value<bool>(&dest.create_info.print_pcs),
      "If 1, print out newly covered PCs. Default to 0.")(
      "print_final_stats", po::value<bool>(&dest.print_final_stats),
      "If 1, print statistics at exit. Default to 0.")(
      "detect_leaks", po::value<bool>(&dest.create_info.detect_leaks),
      "If 1, and if LeakSanitizer is enabled "
      "try to detect memory leaks during fuzzing (i.e. not only at shut down). "
      "Default to 0."
      "(not implemented yet)")(
      "close_fd_mask", po::value<bool>(&dest.create_info.close_fd_mask),
      "If 1, close stdout at startup; "
      "if 2, close stderr; if 3, close both. "
      "Be careful, this will also close e.g. stderr of asan. Default to 0."
      "(not implemented yet)")(
      "seed_inputs",
      po::value<std::vector<std::string>>(&dest.create_info.seed_inputs)
          ->multitoken(),
      "A comma-separated list of input files "
      "to use as an additional seed corpus. Alternatively, an \"@\" followed "
      "by "
      "the name of a file containing the comma-separated list. (not "
      "implemented yet)")(
      "keep_seed", po::value<bool>(&dest.create_info.config.keep_seed),
      "If 1, keep seed inputs in the corpus even if "
      "they do not produce new coverage. When used with |reduce_inputs==1|, "
      "the "
      "seed inputs will never be reduced. This option can be useful when seeds "
      "are"
      "not properly formed for the fuzz target but still have useful snippets. "
      "Default to 0."
      "(not implemented yet)")("cross_over",
                               po::value<bool>(&dest.create_info.do_crossover),
                               "If 1, cross over inputs. Default to 1")(
      "cross_over_uniform_dist",
      po::value<bool>(&dest.create_info.crossover_uniform_dist),
      "Experimental. If 1, use a "
      "uniform probability distribution when choosing inputs to cross over "
      "with. "
      "Some of the inputs in the corpus may never get chosen for mutation "
      "depending on the input mutation scheduling policy. With this flag, all "
      "inputs, regardless of the input mutation scheduling policy, can be "
      "chosen "
      "as an input to cross over with. This can be particularly useful with "
      "|keep_seed==1|; all the initial seed inputs, even though they do not "
      "increase coverage because they are not properly formed, will still be "
      "chosen as an input to cross over with. Default to 0.")(
      "mutate_depth", po::value<unsigned int>(&dest.create_info.mutation_depth),
      "Apply this number of consecutive mutations to each input. Default to "
      "5.")("shuffle", po::value<bool>(&dest.create_info.shuffle),
            "Shuffle inputs at startup. Default to 1.")(
      "prefer_small", po::value<bool>(&dest.create_info.prefer_small),
      "If 1, always prefer smaller inputs during the corpus shuffle. Default "
      "to 0.")(
      "check_input_sha1", po::value<bool>(&dest.create_info.check_input_sha1),
      "If 1, files located under the input directories but the filename "
      "doesn't match to sha1 hash of file contents are ignroed. Otherwise, all "
      "files under the input directories are loaded. Default to 0.");
  po::positional_options_description pd;
  pd.add("input", -1);
  return std::make_tuple(desc, pd);
}
// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
auto postProcess(
    const boost::program_options::options_description &desc,
    const boost::program_options::positional_options_description &pd, int argc,
    const char *argv[], const cli::GlobalFuzzerOptions &global,
    std::function<void(std::string &&)> &&sink, Options &dest) -> bool {
  namespace po = boost::program_options;
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv)
                .options(desc)
                .positional(pd)
                .style(po::command_line_style::default_style |
                       po::command_line_style::allow_long_disguise)
                .run(),
            vm);
  po::notify(vm);

  if (global.logger != utils::Logger::Stdout && global.log_file) {
    std::shared_ptr<std::fstream> fd(new std::fstream(
        global.log_file->string(), std::ios::out | std::ios::binary));
    dest.sink = [fd = std::move(fd)](std::string &&m) {
      *fd << m << std::flush;
    };
  } else {
    dest.sink = std::move(sink);
  }

  if (global.help == 1) {
    std::ostringstream out;
    out << "Usage : " << std::endl;
    out << "  $ fuzzuf [libfuzzer|nezha] -- [options]\n";
    out << desc << std::endl;
    dest.sink(std::string(out.str()));
    return false;
  }

  if (global.executor != fuzzuf::cli::ExecutorKind::NATIVE) {
    EXIT("Unsupported executor: `%s`", global.executor.c_str());
  }

  for (auto &v : dest.raw_targets) {
    DEBUG("[*] dest.raw_targets[] = %s", v.c_str());
  }

  if (dest.create_info.verbosity >= 1U) {
    dest.create_info.config.debug = true;
  }

  if (dest.entropic != 0U) {
    dest.create_info.config.set_entropic(EntropicConfig()
                                             .set_enabled(true)
                                             .set_number_of_rarest_features(10)
                                             .set_feature_frequency_threshold(3)
                                             .set_scale_per_exec_time(false));
  }
  if (dest.input_dir.empty()) {
    dest.input_dir.push_back(global.in_dir);
  }
  dest.create_info.input_dir = dest.input_dir[0];
  fs::create_directories(dest.create_info.input_dir);
  if (dest.exact_output_dir.empty()) {
    auto uuid = to_string(boost::uuids::random_generator()());
    auto exact_path = fs::path(dest.output_dir) / fs::path("crash-" + uuid);
    fs::create_directories(exact_path);
    dest.create_info.output_dir = exact_path;
  } else {
    fs::create_directories(dest.exact_output_dir);
    dest.create_info.output_dir = dest.exact_output_dir;
  }
  std::cout << dest.create_info.output_dir << std::endl;
  constexpr unsigned long long int kilo = 1000ULL;
  constexpr unsigned long long int kilo_in_binary = 1024ULL;
  if (dest.exec_timelimit_s != 0U) {
    dest.create_info.exec_timelimit_ms = dest.exec_timelimit_s * kilo;
  } else if (global.exec_timelimit_ms) {
    dest.create_info.exec_timelimit_ms = *global.exec_timelimit_ms;
  }
  if (dest.exec_memlimit_mb != 0U) {
    dest.create_info.exec_memlimit =
        dest.exec_memlimit_mb * kilo_in_binary * kilo_in_binary;
  } else if (global.exec_memlimit) {
    dest.create_info.exec_memlimit = *global.exec_memlimit;
  }
  std::copy(dest.raw_targets.begin(), dest.raw_targets.end(),
            std::back_inserter(dest.targets));
  std::copy(dest.raw_symcc_targets.begin(), dest.raw_symcc_targets.end(),
            std::back_inserter(dest.targets));
  dest.create_info.target_offset = 0u;
  dest.create_info.target_count = dest.raw_targets.size();
  dest.create_info.symcc_target_offset = dest.raw_targets.size();
  dest.create_info.symcc_target_count = dest.raw_symcc_targets.size();
  std::copy(dest.dicts.begin(), dest.dicts.end(),
            std::back_inserter(dest.create_info.dictionaries));

  if (dest.create_info.seed != 0) {
    dest.rng.seed(dest.create_info.seed);
  } else {
    dest.rng.seed(std::random_device()());
  }
  return true;
}
// NOLINTEND(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

auto loadInitialInputs(Options &dest, std::minstd_rand &rng)
    -> exec_input::ExecInputSet {
  exec_input::ExecInputSet initial_inputs;

  std::size_t input_count = 0U;
  std::vector<utils::mapped_file_t> temp;
  for (auto &d : dest.input_dir) {
    for (const auto &data :
         fuzzuf::utils::LoadInputs(d, dest.create_info.check_input_sha1)) {
      temp.push_back(data);
    }
  }
  if (dest.create_info.shuffle) {
    std::shuffle(temp.begin(), temp.end(), rng);
  }
  if (dest.create_info.prefer_small) {
    std::stable_sort(
        temp.begin(), temp.end(), [](const auto &l, const auto &r) {
          return utils::range::rangeSize(l) < utils::range::rangeSize(r);
        });
  }
  for (auto &data : temp) {
    corpus::addToInitialExecInputSet(initial_inputs, data);
    ++input_count;
  }
  if (input_count == 0) {
    corpus::addToInitialExecInputSet(initial_inputs,
                                     std::vector<std::uint8_t>{'+'});
  }

  if (dest.create_info.max_input_length == 0U) {
    dest.create_info.max_input_length = CalcMaxLength(
        initial_inputs |
        adaptor::exec_input_set_range<true, ExecInputSetRangeInsertMode::NONE>);
  }

  return initial_inputs;
}
}  // namespace fuzzuf::algorithm::libfuzzer
