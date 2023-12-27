/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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

#include "fuzzuf/cli/fuzzer/afl_kscheduler/build_from_args.hpp"

#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/fuzzer.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/option.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/state.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/testcase.hpp"
#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"

namespace fuzzuf::cli::fuzzer::afl_kscheduler {
// Used only for CLI
std::unique_ptr<fuzzuf::fuzzer::Fuzzer> BuildFromArgs(
    const FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  namespace po = boost::program_options;
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  afl::AFLFuzzerOptions afl_options;
  po::options_description fuzzer_desc("AFL options");
  std::vector<std::string> pargs;
  afl_options.forksrv = true;
  fuzzer_desc.add(fuzzer_args.global_options_description)
      .add_options()(
      "forksrv",
      po::value<bool>(&afl_options.forksrv)->default_value(afl_options.forksrv),
      "Enable/disable fork server mode. default is true.")("dict_file,x",
                     po::value<std::vector<std::string>>(&afl_options.dict_file)
                         ->composing(),
                     "Load additional dictionary file.")(
          "pargs", po::value<std::vector<std::string>>(&pargs),
          "Specify PUT and args for PUT.")("det,d",po::bool_switch(),"Quick & dirty mode (skips deterministic steps)")("sequential,s",po::bool_switch(),"Assume basic block ids are sequential")(
          "frida",
          po::value<bool>(&afl_options.frida_mode)
              ->default_value(afl_options.frida_mode),
          "Enable/disable frida mode. Default to false.")("parallel-deterministic,M",
                        po::value<std::string>(&afl_options.instance_id),
                        "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)")(
          "parallel-random,S", po::value<std::string>(&afl_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)");

  po::variables_map vm;
  po::store(po::command_line_parser(fuzzer_args.argc, fuzzer_args.argv)
                .options(fuzzer_desc)
                .positional(pargs_desc)
                .run(),
            vm);
  po::notify(vm);

  if (global_options.help) {
    std::cout << "Help:" << std::endl;
    std::cout << fuzzer_desc << std::endl;
    std::exit(1);
  }

  u32 mem_limit = global_options.exec_memlimit.value_or(fuzzuf::algorithm::afl::option::GetMemLimit<algorithm::afl::option::AFLKSchedulerTag>());
  if (afl_options.frida_mode) {
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
    std::cout << "Help:" << std::endl;
    std::cout << fuzzer_args.global_options_description << std::endl;
    std::exit(1);
  }

  // Trace level log
  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  // Create AFLSetting

  auto setting = std::make_shared< algorithm::afl::AFLSetting >(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(algorithm::afl::option::GetExecTimeout<algorithm::afl::option::AFLKSchedulerTag>()),
      mem_limit, afl_options.forksrv,
      /* dumb_mode */ false,  // FIXME: add dumb_mode
      global_options.cpuid_to_bind);

  // NativeLinuxExecutor needs the directory specified by "out_dir" to be
  // already set up so we need to create the directory first, and then
  // initialize Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;

  std::shared_ptr<executor::AFLExecutorInterface> executor;
  switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
      auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->forksrv, setting->out_dir / GetDefaultOutfile<algorithm::afl::option::AFLKSchedulerTag>(),
          GetMapSize<algorithm::afl::option::AFLKSchedulerTag>(),  // afl_shm_size
          0                      // bb_shm_size
      );
      executor = std::make_shared<executor::AFLExecutorInterface>(std::move(nle));
      break;
    }

    case ExecutorKind::FORKSERVER: {
      auto lfe = std::make_shared<fuzzuf::executor::LinuxForkServerExecutor>(
          fuzzuf::executor::LinuxForkServerExecutorParameters()
              .set_argv(setting->argv)
              .set_exec_timelimit_ms(setting->exec_timelimit_ms)
              .set_exec_memlimit(setting->exec_memlimit)
              .set_path_to_write_input(setting->out_dir /
                                       GetDefaultOutfile<algorithm::afl::option::AFLKSchedulerTag>())
              .set_afl_shm_size(GetMapSize<algorithm::afl::option::AFLKSchedulerTag>())  // afl_shm_size
              .move());
      executor = std::make_shared<executor::AFLExecutorInterface>(std::move(lfe));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming GetMapSize<AFLTag>() == QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<algorithm::afl::option::AFLKSchedulerTag>());
      executor = std::make_shared<executor::AFLExecutorInterface>(std::move(qe));
      break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
      auto cse = std::make_shared<fuzzuf::executor::CoreSightExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<algorithm::afl::option::AFLKSchedulerTag>(),
          GetMapSize<algorithm::afl::option::AFLKSchedulerTag>()  // afl_shm_size
      );
      executor = std::make_shared<executor::AFLExecutorInterface>(std::move(cse));
      break;
    }
#endif

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  auto mutop_optimizer =
      std::shared_ptr<optimizer::Optimizer<u32>>(new algorithm::afl::AFLHavocCaseDistrib());
  std::unique_ptr<optimizer::HavocOptimizer> havoc_optimizer(
      new algorithm::afl::AFLHavocOptimizer(mutop_optimizer, fuzzuf::algorithm::afl::option::GetHavocStackPow2<algorithm::afl::option::AFLKSchedulerTag>()));

  // Create AFLState
  auto state =
      std::make_unique<algorithm::afl_kscheduler::AFLKSchedulerState>(setting, executor, std::move(havoc_optimizer));
  state->skip_deterministic = vm[ "det" ].as<bool>();
  state->enable_sequential_id = vm[ "sequential" ].as<bool>();

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

  return std::unique_ptr<fuzzuf::algorithm::afl_kscheduler::AFLKSchedulerFuzzer>(
      dynamic_cast<fuzzuf::algorithm::afl_kscheduler::AFLKSchedulerFuzzer *>(new fuzzuf::algorithm::afl_kscheduler::AFLKSchedulerFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::afl_kscheduler
