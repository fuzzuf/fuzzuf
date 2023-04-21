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

#ifndef FUZZUF_INCLUDE_CLI_MOPT_BUILD_MOPT_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_MOPT_BUILD_MOPT_FROM_ARGS_HPP

#include <boost/program_options.hpp>
#include <memory>

#include "fuzzuf/algorithms/afl/afl_havoc_optimizer.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/cli/fuzzer/mopt/check_parallel_mode_args.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/parallel_mode.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::cli::fuzzer::mopt {

namespace po = boost::program_options;

struct MOptFuzzerOptions {
  bool forksrv;                        // Optional
  std::vector<std::string> dict_file;  // Optional
  bool frida_mode;                     // Optional
  u64 mopt_limit_time;
  u64 mopt_most_time;
  std::string instance_id;  // Optional
  utils::ParallelModeT parallel_mode =
      utils::ParallelModeT::SINGLE;  // Optional

  // Default values
  MOptFuzzerOptions()
      : forksrv(true),
        frida_mode(false),
        mopt_limit_time(1),
        mopt_most_time(0){};
};

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

// Used only for CLI
template <class TFuzzer, class TMOptFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildMOptFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  MOptFuzzerOptions mopt_options;

  po::options_description fuzzer_desc("MOpt options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()(
      "forksrv",
      po::value<bool>(&mopt_options.forksrv)
          ->default_value(mopt_options.forksrv),
      "Enable/disable fork server mode. default is true.")(
      "dict_file,x",
      po::value<std::vector<std::string>>(&mopt_options.dict_file)->composing(),
      "Load additional dictionary file.")
      // If you want to add fuzzer specific options, add options here
      ("pargs", po::value<std::vector<std::string>>(&pargs),
       "Specify PUT and args for PUT.")(
          "frida",
          po::value<bool>(&mopt_options.frida_mode)
              ->default_value(mopt_options.frida_mode),
          "Enable/disable frida mode. Default to false.")(
          "limit,L",
          po::value<u64>(&mopt_options.mopt_limit_time)
              ->default_value(mopt_options.mopt_limit_time),
          "use MOpt-AFL and set the limit time for entering the pacemaker "
          "fuzzing mode (set 0 will enter pacemaker mode at first). For "
          "instance, (-L 30): if MOpt-AFL finishes the mutation of one input "
          "while does not find any interesting test case for more than 30 min, "
          "MOpt-AFL will enter the pacemaker fuzzing mode (it may take three "
          "or four days for MOpt-AFL to enter the pacemaker fuzzing mode when "
          "'-L 30').")(
          "parallel-deterministic,M",
          po::value<std::string>(&mopt_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)")(
          "parallel-random,S",
          po::value<std::string>(&mopt_options.instance_id),
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
    fuzzuf::cli::fuzzer::mopt::usage(fuzzer_args.global_options_description);
  }

  CheckParallelModeArgs(vm, mopt_options, global_options);

  using fuzzuf::algorithm::afl::option::GetMemLimit;
  using fuzzuf::algorithm::mopt::option::MOptTag;

  u32 mem_limit = global_options.exec_memlimit.value_or(GetMemLimit<MOptTag>());
  if (mopt_options.frida_mode) {
    setenv("__AFL_DEFER_FORKSRV", "1", 1);
    fs::path frida_bin =
        fs::path(fuzzer_args.argv[0]).parent_path() / "afl-frida-trace.so";
    setenv("LD_PRELOAD", frida_bin.c_str(), 1);

    if (mem_limit > 0) {
      struct stat statbuf;
      if ((stat(frida_bin.c_str(), &statbuf)) == -1) {
        std::cerr
            << cLRD << "[-] File afl-frida-trace.so not found\n"
            << "    Build one first with cmake where -DENABLE_FRIDA_TRACE=1"
            << cRST << std::endl;
      }
      // Need to add the size of the library
      mem_limit += statbuf.st_size;
    }
  }

  PutArgs put(pargs);
  try {
    put.Check();
  } catch (const exceptions::cli_error &e) {
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
    fuzzuf::cli::fuzzer::mopt::usage(fuzzer_args.global_options_description);
  }

  // Trace level log
  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::afl::option::GetExecTimeout;
  using fuzzuf::algorithm::mopt::MOptSetting;
  using fuzzuf::algorithm::mopt::option::MOptTag;

  // Create MOptSetting

  auto setting = std::make_shared<const MOptSetting>(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(GetExecTimeout<MOptTag>()),
      mem_limit, mopt_options.forksrv,
      /* dumb_mode */ false,  // FIXME: add dumb_mode
      global_options.cpuid_to_bind, mopt_options.mopt_limit_time,
      mopt_options.mopt_most_time);

  // NativeLinuxExecutor needs the directory specified by "out_dir" to be
  // already set up so we need to create the directory first, and then
  // initialize Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;
  using fuzzuf::cli::ExecutorKind;

  std::shared_ptr<TExecutor> executor;
  switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
      auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->forksrv, setting->out_dir / GetDefaultOutfile<MOptTag>(),
          GetMapSize<MOptTag>(),  // afl_shm_size
          0                       // bb_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(nle));
      break;
    }

    case ExecutorKind::FORKSERVER: {
      auto lfe = std::make_shared<fuzzuf::executor::LinuxForkServerExecutor>(
          fuzzuf::executor::LinuxForkServerExecutorParameters()
              .set_argv(setting->argv)
              .set_exec_timelimit_ms(setting->exec_timelimit_ms)
              .set_exec_memlimit(setting->exec_memlimit)
              .set_path_to_write_input(setting->out_dir /
                                       GetDefaultOutfile<MOptTag>())
              .set_afl_shm_size(GetMapSize<MOptTag>())  // afl_shm_size
              .move());
      executor = std::make_shared<TExecutor>(std::move(lfe));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming GetMapSize<MOptTag>() == QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<MOptTag>());
      executor = std::make_shared<TExecutor>(std::move(qe));
      break;
    }

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  using algorithm::afl::AFLHavocOptimizer;
  using algorithm::afl::option::GetHavocStackPow2;

  auto mutop_optimizer = std::make_shared<optimizer::MOptOptimizer>();
  std::unique_ptr<optimizer::HavocOptimizer> havoc_optimizer(
      new AFLHavocOptimizer(mutop_optimizer, GetHavocStackPow2<MOptTag>()));

  // Create MOptState
  using fuzzuf::algorithm::mopt::MOptState;
  auto state = std::make_unique<MOptState>(
      setting, executor, std::move(havoc_optimizer), mutop_optimizer);

  // Load dictionary
  for (const auto &d : mopt_options.dict_file) {
    using fuzzuf::algorithm::afl::dictionary::AFLDictData;

    const std::function<void(std::string &&)> f = [](std::string s) {
      ERROR("Dictionary error: %s", s.c_str());
    };

    fuzzuf::algorithm::afl::dictionary::load(d, state->extras, false, f);
  }
  fuzzuf::algorithm::afl::dictionary::SortDictByLength(state->extras);

  if (mopt_options.parallel_mode != utils::ParallelModeT::SINGLE) {
    state->sync_external_queue = true;
    state->sync_id = mopt_options.instance_id;
  }

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TMOptFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::mopt

#endif
