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

#ifndef FUZZUF_INCLUDE_CLI_FUZZER_AFLPLUSPLUS_BUILD_AFLPLUSPLUS_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_AFLPLUSPLUS_BUILD_AFLPLUSPLUS_FROM_ARGS_HPP

#include "fuzzuf/algorithms/afl/afl_havoc_case_distrib.hpp"
#include "fuzzuf/algorithms/afl/afl_havoc_optimizer.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_option.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_setting.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/cli/fuzzer/aflplusplus/check_parallel_mode_args.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/optimizer/slopt/slopt_optimizer.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/parallel_mode.hpp"
#include "fuzzuf/utils/workspace.hpp"
#ifdef __aarch64__
#include "fuzzuf/executor/coresight_executor.hpp"
#endif
#include <boost/program_options.hpp>

namespace fuzzuf::cli::fuzzer::aflplusplus {

namespace po = boost::program_options;

struct AFLplusplusFuzzerOptions {
  bool forksrv;                        // Optional
  std::vector<std::string> dict_file;  // Optional
  bool frida_mode;                     // Optional
  bool use_slopt;                      // Optional
  std::string schedule;                // Optional
  std::string instance_id;             // Optional
  utils::ParallelModeT parallel_mode =
      utils::ParallelModeT::SINGLE;  // Optional
  // Default values
  AFLplusplusFuzzerOptions()
      : forksrv(true), frida_mode(false), schedule("fast"){};
};

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

// Used only for CLI
template <class TFuzzer, class TAFLFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildAFLplusplusFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  AFLplusplusFuzzerOptions aflplusplus_options;

  po::options_description fuzzer_desc("AFLplusplus options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()(
      "forksrv",
      po::value<bool>(&aflplusplus_options.forksrv)
          ->default_value(aflplusplus_options.forksrv),
      "Enable/disable fork server mode. default is true.")(
      "dict_file,x",
      po::value<std::vector<std::string>>(&aflplusplus_options.dict_file)
          ->composing(),
      "Load additional dictionary file.")
      // If you want to add fuzzer specific options, add options here
      ("slopt",
       po::value<bool>(&aflplusplus_options.use_slopt)
           ->default_value(aflplusplus_options.use_slopt),
       "Do/don't use SLOPT as mutation operator optimizer. default is false.")(
          "pargs", po::value<std::vector<std::string>>(&pargs),
          "Specify PUT and args for PUT.")(
          "frida",
          po::value<bool>(&aflplusplus_options.frida_mode)
              ->default_value(aflplusplus_options.frida_mode),
          "Enable/disable frida mode. Default to false.")(
          "det,D",
          "Do not skip deterministic stages if specified (AFLplusplus skips "
          "them by default)")(
          "schedule,p",
          po::value<std::string>(&aflplusplus_options.schedule)
              ->default_value(aflplusplus_options.schedule),
          "Power schedule to use. Available values are:\n"
          "fast (default), coe, explore, lin, quad, exploit")(
          "parallel-deterministic,M",
          po::value<std::string>(&aflplusplus_options.instance_id),
          "distributed mode (see docs/algorithms/afl/parallel_fuzzing.md)")(
          "parallel-random,S",
          po::value<std::string>(&aflplusplus_options.instance_id),
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
    fuzzuf::cli::fuzzer::aflplusplus::usage(
        fuzzer_args.global_options_description);
  }

  CheckParallelModeArgs(vm, aflplusplus_options, global_options);

  using fuzzuf::algorithm::afl::option::GetMemLimit;
  using fuzzuf::algorithm::aflplusplus::option::AFLplusplusTag;

  u32 mem_limit =
      global_options.exec_memlimit.value_or(GetMemLimit<AFLplusplusTag>());
  if (aflplusplus_options.frida_mode) {
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
    fuzzuf::cli::fuzzer::aflplusplus::usage(
        fuzzer_args.global_options_description);
  }

  // Trace level log
  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::afl::option::GetExecTimeout;
  using fuzzuf::algorithm::aflplusplus::AFLplusplusSetting;

  // Create AFLplusplusSetting

  fuzzuf::algorithm::aflfast::option::Schedule schedule;
  if (!aflplusplus_options.schedule.compare("fast")) {
    schedule = fuzzuf::algorithm::aflfast::option::FAST;
  } else if (!aflplusplus_options.schedule.compare("coe")) {
    schedule = fuzzuf::algorithm::aflfast::option::COE;
  } else if (!aflplusplus_options.schedule.compare("explore")) {
    schedule = fuzzuf::algorithm::aflfast::option::EXPLORE;
  } else if (!aflplusplus_options.schedule.compare("lin")) {
    schedule = fuzzuf::algorithm::aflfast::option::LIN;
  } else if (!aflplusplus_options.schedule.compare("quad")) {
    schedule = fuzzuf::algorithm::aflfast::option::QUAD;
  } else if (!aflplusplus_options.schedule.compare("exploit")) {
    schedule = fuzzuf::algorithm::aflfast::option::EXPLOIT;
  } else {
    std::cout << cLRD "[-] Unknown power schedule!"
              << "(" << aflplusplus_options.schedule << ")" cRST << std::endl;
    std::exit(1);
  }

  auto setting = std::make_shared<const AFLplusplusSetting>(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(
          GetExecTimeout<AFLplusplusTag>()),
      mem_limit, aflplusplus_options.forksrv,
      /* dumb_mode */ false,  // FIXME: add dumb_mode
      global_options.cpuid_to_bind, schedule, aflplusplus_options.schedule);

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
          setting->forksrv,
          setting->out_dir / GetDefaultOutfile<AFLplusplusTag>(),
          GetMapSize<AFLplusplusTag>(),  // afl_shm_size
          0                              // bb_shm_size
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
                                       GetDefaultOutfile<AFLplusplusTag>())
              .set_afl_shm_size(GetMapSize<AFLplusplusTag>())  // afl_shm_size
              .move());
      executor = std::make_shared<TExecutor>(std::move(lfe));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming GetMapSize<AFLplusplusTag>() ==
      // QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<AFLplusplusTag>());
      executor = std::make_shared<TExecutor>(std::move(qe));
      break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
      auto cse = std::make_shared<fuzzuf::executor::CoreSightExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<AFLplusplusTag>(),
          GetMapSize<AFLplusplusTag>()  // afl_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(cse));
      break;
    }
#endif

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  std::unique_ptr<optimizer::HavocOptimizer> havoc_optimizer;

  if (aflplusplus_options.use_slopt) {
    using algorithm::afl::option::GetHavocStackPow2;
    using algorithm::afl::option::GetMaxFile;
    using algorithm::aflplusplus::havoc::AFLPLUSPLUS_NUM_CASE;

    havoc_optimizer.reset(new optimizer::slopt::SloptOptimizer(
        AFLPLUSPLUS_NUM_CASE, GetMaxFile<AFLplusplusTag>(),
        GetHavocStackPow2<AFLplusplusTag>()));
  } else {
    using algorithm::afl::AFLHavocOptimizer;
    using algorithm::afl::option::GetHavocStackPow2;
    using algorithm::aflplusplus::havoc::AFLplusplusHavocCaseDistrib;

    std::unique_ptr<optimizer::Optimizer<u32>> mutop_optimizer(
        new AFLplusplusHavocCaseDistrib());
    havoc_optimizer.reset(new AFLHavocOptimizer(
        std::move(mutop_optimizer), GetHavocStackPow2<AFLplusplusTag>()));
  }

  // Create AFLplusplusState
  using fuzzuf::algorithm::aflplusplus::AFLplusplusState;
  auto state = std::make_unique<AFLplusplusState>(setting, executor,
                                                  std::move(havoc_optimizer));

  state->skip_deterministic = !vm.count("det");

  // Load dictionary
  for (const auto &d : aflplusplus_options.dict_file) {
    using fuzzuf::algorithm::afl::dictionary::AFLDictData;

    const std::function<void(std::string &&)> f = [](std::string s) {
      ERROR("Dictionary error: %s", s.c_str());
    };

    fuzzuf::algorithm::afl::dictionary::load(d, state->extras, false, f);
  }
  fuzzuf::algorithm::afl::dictionary::SortDictByLength(state->extras);

  if (aflplusplus_options.parallel_mode != utils::ParallelModeT::SINGLE) {
    state->sync_external_queue = true;
    state->sync_id = aflplusplus_options.instance_id;
  }

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TAFLFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::aflplusplus

#endif
