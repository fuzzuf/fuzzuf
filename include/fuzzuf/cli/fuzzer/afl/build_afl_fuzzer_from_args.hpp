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

#ifndef FUZZUF_INCLUDE_CLI_FUZZER_AFL_BUILD_AFL_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_AFL_BUILD_AFL_FROM_ARGS_HPP

#include "fuzzuf/algorithms/afl/afl_havoc_case_distrib.hpp"
#include "fuzzuf/algorithms/afl/afl_havoc_optimizer.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/cli/fuzzer/afl/check_parallel_mode_args.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/parallel_mode.hpp"
#include "fuzzuf/utils/workspace.hpp"
#ifdef __aarch64__
#include "fuzzuf/executor/coresight_executor.hpp"
#endif
#include <boost/program_options.hpp>

namespace fuzzuf::cli::fuzzer::afl {

namespace po = boost::program_options;

struct AFLFuzzerOptions {
  bool forksrv;                        // Optional
  std::vector<std::string> dict_file;  // Optional
  bool frida_mode;                     // Optional
  std::string instance_id;             // Optional
  utils::ParallelModeT parallel_mode =
      utils::ParallelModeT::SINGLE;  // Optional
  // Default values
  AFLFuzzerOptions() : forksrv(true), frida_mode(false){};
};

template <class TFuzzer, class TAFLFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildFuzzer(
    const char *prog_name,
    const boost::program_options::options_description &option_description,
    const AFLFuzzerOptions &afl_options, const std::vector<std::string> &pargs,
    const GlobalFuzzerOptions &global_options);

// Used only for CLI
template <class TFuzzer, class TAFLFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildAFLFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  AFLFuzzerOptions afl_options;

  po::options_description fuzzer_desc("AFL options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()(
      "forksrv",
      po::value<bool>(&afl_options.forksrv)->default_value(afl_options.forksrv),
      "Enable/disable fork server mode. default is true.")(
      "dict_file,x",
      po::value<std::vector<std::string>>(&afl_options.dict_file)->composing(),
      "Load additional dictionary file.")(
      "pargs", po::value<std::vector<std::string>>(&pargs),
      "Specify PUT and args for PUT.")(
      "frida",
      po::value<bool>(&afl_options.frida_mode)
          ->default_value(afl_options.frida_mode),
      "Enable/disable frida mode. Default to false.")(
      "parallel-deterministic,M",
      po::value<std::string>(&afl_options.instance_id),
      "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)")(
      "parallel-random,S", po::value<std::string>(&afl_options.instance_id),
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
    std::cout << "Help:" << std::endl;
    std::cout << fuzzer_args.global_options_description << std::endl;
    std::exit(1);
  }

  CheckParallelModeArgs(vm, afl_options, global_options);

  return BuildFuzzer<TFuzzer, TAFLFuzzer, TExecutor>(
      fuzzer_args.argv[0], fuzzer_args.global_options_description, afl_options,
      pargs, global_options);
}

template <class TFuzzer, class TAFLFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildFuzzer(
    const char *prog_name,
    const boost::program_options::options_description &option_description,
    const AFLFuzzerOptions &afl_options, const std::vector<std::string> &pargs,
    const GlobalFuzzerOptions &global_options) {
  using algorithm::afl::option::AFLTag;
  using algorithm::afl::option::GetMemLimit;

  u32 mem_limit = global_options.exec_memlimit.value_or(GetMemLimit<AFLTag>());
  if (afl_options.frida_mode) {
    setenv("__AFL_DEFER_FORKSRV", "1", 1);
    fs::path frida_bin =
        fs::path(prog_name).parent_path() / "afl-frida-trace.so";
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
    std::cout << "Help:" << std::endl;
    std::cout << option_description << std::endl;
    std::exit(1);
  }

  // Trace level log
  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::afl::AFLSetting;
  using fuzzuf::algorithm::afl::option::GetExecTimeout;

  // Create AFLSetting

  auto setting = std::make_shared<const AFLSetting>(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(GetExecTimeout<AFLTag>()),
      mem_limit, afl_options.forksrv,
      /* dumb_mode */ false,  // FIXME: add dumb_mode
      global_options.cpuid_to_bind);

  // NativeLinuxExecutor needs the directory specified by "out_dir" to be
  // already set up so we need to create the directory first, and then
  // initialize Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;

  std::shared_ptr<TExecutor> executor;
  switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
      auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->forksrv, setting->out_dir / GetDefaultOutfile<AFLTag>(),
          GetMapSize<AFLTag>(),  // afl_shm_size
          0                      // bb_shm_size
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
                                       GetDefaultOutfile<AFLTag>())
              .set_afl_shm_size(GetMapSize<AFLTag>())  // afl_shm_size
              .move());
      executor = std::make_shared<TExecutor>(std::move(lfe));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming GetMapSize<AFLTag>() == QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<AFLTag>());
      executor = std::make_shared<TExecutor>(std::move(qe));
      break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
      auto cse = std::make_shared<fuzzuf::executor::CoreSightExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<AFLTag>(),
          GetMapSize<AFLTag>()  // afl_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(cse));
      break;
    }
#endif

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  using algorithm::afl::AFLHavocCaseDistrib;
  using algorithm::afl::AFLHavocOptimizer;
  using algorithm::afl::option::GetHavocStackPow2;

  auto mutop_optimizer =
      std::shared_ptr<optimizer::Optimizer<u32>>(new AFLHavocCaseDistrib());
  std::unique_ptr<optimizer::HavocOptimizer> havoc_optimizer(
      new AFLHavocOptimizer(mutop_optimizer, GetHavocStackPow2<AFLTag>()));

  // Create AFLState
  using fuzzuf::algorithm::afl::AFLState;
  auto state =
      std::make_unique<AFLState>(setting, executor, std::move(havoc_optimizer));

  // Load dictionary
  for (const auto &d : afl_options.dict_file) {
    using fuzzuf::algorithm::afl::dictionary::AFLDictData;

    const std::function<void(std::string &&)> f = [](std::string s) {
      ERROR("Dictionary error: %s", s.c_str());
    };

    fuzzuf::algorithm::afl::dictionary::load(d, state->extras, false, f);
  }
  fuzzuf::algorithm::afl::dictionary::SortDictByLength(state->extras);

  if (afl_options.parallel_mode != utils::ParallelModeT::SINGLE) {
    state->sync_external_queue = true;
    state->sync_id = afl_options.instance_id;
  }

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TAFLFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::afl

#endif
