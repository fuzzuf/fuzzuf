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
 * @file build_nautilus_fuzzer_from_args.hpp
 * @brief Register CLI option for Nautilus
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_CLI_FUZZER_NAUTILUS_BUILD_NAUTILUS_FUZZER_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_FUZZER_NAUTILUS_BUILD_NAUTILUS_FUZZER_FROM_ARGS_HPP

#include <boost/program_options.hpp>
#include <iostream>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/option.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/setting.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/executor/qemu_executor.hpp"
#ifdef __aarch64__
#include "fuzzuf/executor/coresight_executor.hpp"
#endif
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/optparser.hpp"

namespace fuzzuf::cli::fuzzer::nautilus {

namespace po = boost::program_options;

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

using fuzzuf::algorithm::nautilus::fuzzer::NautilusFuzzer;

/**
 * @fn
 * @brief Build Nautilus fuzzer instance from CLI arguments
 * @param (fuzzer_args) Arguments passed to Nautilus
 * @param (global_options) Global options
 */
template <class TFuzzer, class TNautilusFuzzer, class TExecutor>
std::unique_ptr<TFuzzer> BuildNautilusFuzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  /* Options */
  bool forksrv;
  std::string path_to_grammar;
  u64 bitmap_size, number_of_deterministic_mutations, max_tree_size;
  u16 number_of_generate_inputs;

  /* Set up additional options for Nautilus */
  using namespace fuzzuf::algorithm::nautilus::fuzzer::option;
  using fuzzuf::cli::ExecutorKind;

  po::options_description fuzzer_desc("Nautilus options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()
      /* Path to grammar file */
      ("grammar",
       po::value<std::string>(&path_to_grammar)
           ->value_name("GRAMMAR")
           ->required(),
       "Path to grammar file (.json)")

      /* Bitmap size */
      ("bitmap-size",
       po::value<u64>(&bitmap_size)
           ->value_name("SIZE")
           ->default_value(GetDefaultBitmapSize()),
       "Bitmap size")

      /* Number of generate inputs */
      ("generate-num",
       po::value<u16>(&number_of_generate_inputs)
           ->value_name("NUM")
           ->default_value(GetDefaultNumOfGenInputs()),
       "Number of inputs to be generated for each generation phase")

      /* Number of deterministic mutations */
      ("detmut-num",
       po::value<u64>(&number_of_deterministic_mutations)
           ->value_name("NUM")
           ->default_value(GetDefaultNumOfDetMuts()),
       "Number of deterministic mutations")

      /* Maximum size of tree */
      ("max-tree-size",
       po::value<u64>(&max_tree_size)
           ->value_name("NUM")
           ->default_value(GetDefaultMaxTreeSize()),
       "Maximum size of tree (The larger this size is, the longer the input "
       "will be.)")

      /* Fork server mode */
      ("forksrv", po::value<bool>(&forksrv)->default_value(true),
       "Enable/disable fork server mode. Default to true. (not recommended to "
       "disable)")

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

  if (global_options.help) {
    fuzzuf::cli::fuzzer::nautilus::usage(
        fuzzer_args.global_options_description);
  }

  if (global_options.executor == ExecutorKind::QEMU) {
    bitmap_size = fuzzuf::executor::QEMUExecutor::QEMU_SHM_SIZE;
  }

  po::notify(vm);

  PutArgs put(pargs);
  try {
    put.Check();
  } catch (const exceptions::cli_error &e) {
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
    fuzzuf::cli::fuzzer::nautilus::usage(
        fuzzer_args.global_options_description);
  }

  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::afl::option::GetExecTimeout;
  using fuzzuf::algorithm::afl::option::GetMemLimit;
  using fuzzuf::algorithm::nautilus::fuzzer::NautilusSetting;

  /* Create setting for Nautilus */
  std::shared_ptr<const NautilusSetting> setting(new NautilusSetting(
      put.Args(),
      path_to_grammar,  // TODO: check if empty
      global_options.out_dir,
      global_options.exec_timelimit_ms.value_or(GetExecTimeout<NautilusTag>()),
      global_options.exec_memlimit.value_or(GetMemLimit<NautilusTag>()),
      forksrv, global_options.cpuid_to_bind,

      // TODO: Change here if threading is supported
      GetDefaultNumOfThreads(), GetDefaultThreadSize(),
      number_of_generate_inputs, number_of_deterministic_mutations,
      max_tree_size, bitmap_size));

  /* Craete output directories */
  std::vector<std::string> folders{"signaled", "queue", "timeout", "chunks"};
  for (auto f : folders) {
    fs::create_directories(fuzzuf::utils::StrPrintf(
        "%s/%s", setting->path_to_workdir.c_str(), f.c_str()));
  }

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;

  std::shared_ptr<TExecutor> executor;
  switch (global_options.executor) {
    case ExecutorKind::NATIVE: {
      auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
          put.Args(), setting->exec_timeout_ms, setting->exec_memlimit,
          setting->forksrv,
          setting->path_to_workdir / GetDefaultOutfile<NautilusTag>(),
          setting->bitmap_size,  // afl_shm_size used as bitmap_size
          0                      // bb_shm_size is not used
      );
      executor = std::make_shared<TExecutor>(std::move(nle));
      break;
    }

    case ExecutorKind::QEMU: {
      // NOTE: Assuming setting->bitmap_size == QEMUExecutor::QEMU_SHM_SIZE
      auto qe = std::make_shared<fuzzuf::executor::QEMUExecutor>(
          global_options.proxy_path.value(), put.Args(),
          setting->exec_timeout_ms, setting->exec_memlimit, setting->forksrv,
          setting->path_to_workdir / GetDefaultOutfile<NautilusTag>());
      executor = std::make_shared<TExecutor>(std::move(qe));
      break;
    }

#ifdef __aarch64__
    case ExecutorKind::CORESIGHT: {
      auto cse = std::make_shared<fuzzuf::executor::CoreSightExecutor>(
          global_options.proxy_path.value(), put.Args(),
          setting->exec_timeout_ms, setting->exec_memlimit, setting->forksrv,
          setting->path_to_workdir / GetDefaultOutfile<NautilusTag>(),
          setting->bitmap_size  // afl_shm_size used as bitmap_size
      );
      executor = std::make_shared<TExecutor>(std::move(cse));
      break;
    }
#endif

    default:
      EXIT("Unsupported executor: '%s'", global_options.executor.c_str());
  }

  using fuzzuf::algorithm::nautilus::fuzzer::NautilusState;
  using fuzzuf::algorithm::nautilus::grammartec::ChunkStore;

  /* Create state for Nautilus */
  auto state = std::make_unique<NautilusState>(setting, executor);

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TNautilusFuzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::nautilus

#endif
