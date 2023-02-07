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
 * @file build_die_fuzzer_from_args.hpp
 * @brief Register CLI option for DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <boost/program_options.hpp>
#include <iostream>

#include "fuzzuf/algorithms/die/die_option.hpp"
#include "fuzzuf/algorithms/die/die_setting.hpp"
#include "fuzzuf/algorithms/die/die_state.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#ifdef __aarch64__
#include "fuzzuf/executor/coresight_executor.hpp"
#endif
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/which.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::cli::fuzzer::die {

namespace po = boost::program_options;

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

using fuzzuf::algorithm::die::DIEFuzzer;

struct DIEOptions {
  /* Additional options */
  std::string die_dir;     // (optional) Path to DIE fuzzer
  std::string cmd_py;      // (optional) Command to execute Python
  std::string cmd_node;    // (optional) Command to execute JavaScript
  std::string d8_path;     // (optional) Path to d8
  std::string d8_flags;    // (optional) Flags for d8
  std::string typer_path;  // (optional) Path to die_typer.py
  int mut_cnt;             // (optional) Mutation count

  /* Default values */
  DIEOptions()
      : die_dir("tools/die/DIE"),
        d8_flags(""),
        typer_path("tools/die/typer.py"),
        mut_cnt(100){};
};

/**
 * @fn
 * @brief Build DIE fuzzer instance from CLI arguments
 * @param (fuzzer_args) Arguments passed to DIE
 * @param (global_options) Global options
 */
template <class TFuzzer, class TDIEFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildDIEFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  DIEOptions die_options;

  /* Set up additional options for DIE */
  po::options_description fuzzer_desc("DIE options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()("die_dir",
                            po::value<std::string>(&die_options.die_dir),
                            "Set path to DIE fuzzer.\nDefault: tools/die/DIE")(
      "python", po::value<std::string>(&die_options.cmd_py),
      "Set command to execute Python 3.\nDefault: python3")(
      "node", po::value<std::string>(&die_options.cmd_node),
      "Set command to execute DIE fuzzer.\nDefault: node")(
      "d8", po::value<std::string>(&die_options.d8_path),
      "Set path to d8 used for instrumentation.\nPUT is used if not "
      "speicified")(
      "d8_flags", po::value<std::string>(&die_options.d8_flags),
      "Set command line options passed to d8 on instrumentation.")(
      "typer", po::value<std::string>(&die_options.typer_path),
      "Set path to python script to collect type information.\nDefault: "
      "tools/die/typer.py")(
      "mut_cnt", po::value<int>(&die_options.mut_cnt),
      "Set number of scripts to generate per mutation.\nDefault: 100")
      //
      ("pargs", po::value<std::vector<std::string>>(&pargs),
       "Specify PUT and args for PUT.");

  po::variables_map vm;
  po::store(
      po::command_line_parser(fuzzer_args.argc, fuzzer_args.argv)
          .options(fuzzer_args.global_options_description.add(fuzzer_desc))
          .positional(pargs_desc)
          .run(),
      vm);
  po::notify(vm);

  if (global_options.help) {
    fuzzuf::cli::fuzzer::die::usage(fuzzer_args.global_options_description);
  }

  PutArgs put(pargs);
  try {
    put.Check();
  } catch (const exceptions::cli_error &e) {
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
    fuzzuf::cli::fuzzer::die::usage(fuzzer_args.global_options_description);
  }

  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  if (die_options.mut_cnt <= 0) {
    /* Mutation count must be positive */
    std::cerr << "[!] `--mut_cnt` requires a positive integer" << std::endl;
    fuzzuf::cli::fuzzer::die::usage(fuzzer_args.global_options_description);
  }

  if (die_options.d8_path.empty()) {
    /* Use target PUT instead of d8 if not specified */
    die_options.d8_path = pargs[0];
  }

  if (die_options.cmd_py.empty()) {
    /* Search python */
    die_options.cmd_py = fuzzuf::utils::which("python3").string();
  }

  if (die_options.cmd_node.empty()) {
    /* Search node */
    die_options.cmd_node = fuzzuf::utils::which("node").string();
  }

  using fuzzuf::algorithm::afl::option::GetExecTimeout;
  using fuzzuf::algorithm::afl::option::GetMemLimit;
  using fuzzuf::algorithm::die::DIESetting;
  using fuzzuf::algorithm::die::option::DIETag;

  /* Create setting for DIE */
  auto setting = std::make_shared<const DIESetting>(
      put.Args(), global_options.in_dir, global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(GetExecTimeout<DIETag>()),
      global_options.exec_memlimit.value_or(GetMemLimit<DIETag>()),
      /* forksrv */ true,
      /* dumb_mode */ false, global_options.cpuid_to_bind,
      die_options.die_dir,  // vvv DIE vvv
      die_options.cmd_py, die_options.cmd_node, die_options.d8_path,
      die_options.d8_flags, die_options.typer_path, die_options.mut_cnt);

  /* NativeLinuxExecutor requires output directory */
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;
  using fuzzuf::cli::ExecutorKind;

  std::shared_ptr<TExecutor> executor;
  switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
      auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->forksrv, setting->out_dir / GetDefaultOutfile<DIETag>(),
          GetMapSize<DIETag>(),  // afl_shm_size
          0                      // bb_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(nle));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming GetMapSize<DIETag>() == QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<DIETag>());
      executor = std::make_shared<TExecutor>(std::move(qe));
      break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
      auto cse = std::make_shared<fuzzuf::executor::CoreSightExecutor>(
          global_options.proxy_path.value(), setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit, setting->forksrv,
          setting->out_dir / GetDefaultOutfile<DIETag>(),
          GetMapSize<DIETag>()  // afl_shm_size
      );
      executor = std::make_shared<TExecutor>(std::move(cse));
      break;
    }
#endif

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  using fuzzuf::algorithm::die::DIEState;

  /* Create state for DIE */
  auto state = std::make_unique<DIEState>(setting, executor);

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TDIEFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::die
