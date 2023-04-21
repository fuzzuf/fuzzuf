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

#ifndef FUZZUF_INCLUDE_CLI_IJON_BUILD_IJON_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_IJON_BUILD_IJON_FROM_ARGS_HPP

#include <boost/program_options.hpp>
#include <memory>

#include "fuzzuf/algorithms/afl/afl_havoc_optimizer.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_havoc.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_state.hpp"
#include "fuzzuf/cli/fuzzer/ijon/check_parallel_mode_args.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/parallel_mode.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::cli::fuzzer::ijon {

namespace po = boost::program_options;

struct IJONFuzzerOptions {
  bool forksrv;                        // Optional
  std::vector<std::string> dict_file;  // Optional
  std::string instance_id;             // Optional
  utils::ParallelModeT parallel_mode =
      utils::ParallelModeT::SINGLE;  // Optional

  // Default values
  IJONFuzzerOptions() : forksrv(true) {}
};

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

// Used only for CLI
template <class TFuzzer, class TIJONFuzzer>
std::unique_ptr<TFuzzer> BuildIJONFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  IJONFuzzerOptions ijon_options;

  po::options_description fuzzer_desc("IJON options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()(
      "forksrv",
      po::value<bool>(&ijon_options.forksrv)
          ->default_value(ijon_options.forksrv),
      "Enable/disable fork server mode. default is true.")(
      "dict_file,x",
      po::value<std::vector<std::string>>(&ijon_options.dict_file)->composing(),
      "Load additional dictionary file.")
      // If you want to add fuzzer specific options, add options here
      ("pargs", po::value<std::vector<std::string>>(&pargs),
       "Specify PUT and args for PUT.")(
          "parallel-deterministic,M",
          po::value<std::string>(&ijon_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)")(
          "parallel-random,S",
          po::value<std::string>(&ijon_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)");

  po::variables_map vm;
  po::store(
      po::command_line_parser(fuzzer_args.argc, fuzzer_args.argv)
          .options(fuzzer_args.global_options_description.add(fuzzer_desc))
          .positional(pargs_desc)
          .run(),
      vm);
  po::notify(vm);

  if (global_options.help) {
    usage(fuzzer_args.global_options_description);
  }

  CheckParallelModeArgs(vm, ijon_options, global_options);

  PutArgs put(pargs);
  try {
    put.Check();
  } catch (const exceptions::cli_error &e) {
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
    usage(fuzzer_args.global_options_description);
  }

  // Trace level log
  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::afl::AFLSetting;
  using fuzzuf::algorithm::afl::option::GetExecTimeout;
  using fuzzuf::algorithm::afl::option::GetMemLimit;
  using fuzzuf::algorithm::ijon::option::IJONTag;

  // Create AFLSetting

  auto setting = std::make_shared<const AFLSetting>(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(GetExecTimeout<IJONTag>()),
      global_options.exec_memlimit.value_or(GetMemLimit<IJONTag>()),
      ijon_options.forksrv,
      /* dumb_mode */ false,  // FIXME: add dumb_mode
      global_options.cpuid_to_bind);

  // NativeLinuxExecutor needs the directory specified by "out_dir" to be
  // already set up so we need to create the directory first, and then
  // initialize Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::executor::IJONExecutorInterface;

  std::shared_ptr<IJONExecutorInterface> executor;
  u32 ijon_max_offset = 0u;
  switch (global_options.executor) {
    case ExecutorKind::FORKSERVER: {
      auto params =
          fuzzuf::executor::LinuxForkServerExecutorParameters()
              .set_argv(setting->argv)
              .set_exec_timelimit_ms(setting->exec_timelimit_ms)
              .set_exec_memlimit(setting->exec_memlimit)
              .set_path_to_write_input(setting->out_dir /
                                       GetDefaultOutfile<IJONTag>())
              .set_afl_shm_size(fuzzuf::algorithm::afl::option::GetMapSize<
                                fuzzuf::algorithm::ijon::option::IJONTag>())
              .set_ijon_counter_shm_size(
                  fuzzuf::algorithm::afl::option::GetMapSize<
                      fuzzuf::algorithm::ijon::option::IJONTag>())
              .set_ijon_max_shm_size(
                  sizeof(u64) *
                  fuzzuf::algorithm::ijon::option::GetMaxMapSize<
                      fuzzuf::algorithm::ijon::option::IJONTag>());
      ijon_max_offset = params.GetIjonMaxOffset();
      auto lfe = std::shared_ptr<fuzzuf::executor::LinuxForkServerExecutor>(
          new fuzzuf::executor::LinuxForkServerExecutor(params.move()));
      executor = std::make_shared<IJONExecutorInterface>(std::move(lfe));
      break;
    }

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  using algorithm::afl::AFLHavocOptimizer;
  using algorithm::afl::option::GetHavocStackPow2;
  using algorithm::ijon::havoc::IJONHavocCaseDistrib;

  auto mutop_optimizer =
      std::unique_ptr<optimizer::Optimizer<u32>>(new IJONHavocCaseDistrib());
  std::unique_ptr<optimizer::HavocOptimizer> havoc_optimizer(
      new AFLHavocOptimizer(std::move(mutop_optimizer),
                            GetHavocStackPow2<IJONTag>()));

  // Create IJONState
  using fuzzuf::algorithm::ijon::IJONState;
  auto state = std::make_unique<IJONState>(setting, executor,
                                           std::move(havoc_optimizer));

  // Load dictionary
  for (const auto &d : ijon_options.dict_file) {
    using fuzzuf::algorithm::afl::dictionary::AFLDictData;

    const std::function<void(std::string &&)> f = [](std::string s) {
      ERROR("Dictionary error: %s", s.c_str());
    };

    fuzzuf::algorithm::afl::dictionary::load(d, state->extras, false, f);
  }
  fuzzuf::algorithm::afl::dictionary::SortDictByLength(state->extras);

  if (ijon_options.parallel_mode != utils::ParallelModeT::SINGLE) {
    state->sync_external_queue = true;
    state->sync_id = ijon_options.instance_id;
  }

  return std::unique_ptr<TFuzzer>(dynamic_cast<TFuzzer *>(
      new TIJONFuzzer(std::move(state), ijon_max_offset)));
}

}  // namespace fuzzuf::cli::fuzzer::ijon

#endif
