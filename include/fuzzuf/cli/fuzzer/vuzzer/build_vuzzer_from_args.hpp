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
 * @file BuildVUzzerFromArgs.hpp
 * @brief Build CLI options for VUzzer
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_CLI_VUZZER_BUILD_VUZZER_FROM_ARGS_HPP
#define FUZZUF_INCLUDE_CLI_VUZZER_BUILD_VUZZER_FROM_ARGS_HPP

#include <boost/program_options.hpp>

#include "config.h"
#include "fuzzuf/algorithms/vuzzer/vuzzer.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_setting.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/put_args.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/executor/polytracker_executor.hpp"
#include "fuzzuf/utils/optparser.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::cli::fuzzer::vuzzer {

namespace po = boost::program_options;

// Fuzzer specific help
// TODO: Provide better help message
static void usage(po::options_description &desc) {
  std::cout << "Help:" << std::endl;
  std::cout << desc << std::endl;
  exit(1);
}

using fuzzuf::algorithm::vuzzer::VUzzer;

struct VUzzerOptions {
  std::string full_dict;               // Optional
  std::string unique_dict;             // Optional
  std::string weight;                  // Optional
  std::string inst_bin;                // Optional
  std::string taint_db;                // Optional
  std::string taint_out;               // Optional
  std::vector<std::string> dict_file;  // Optional

  // Default values
  VUzzerOptions()
      : full_dict("./full.dict"),
        unique_dict("./unique.dict"),
        weight("./weight"),
        inst_bin("./instrumented.bin"),
        taint_db("/mnt/polytracker/polytracker.db"),
        taint_out("/tmp/taint.out"){};
};

// Used only for CLI
template <class TFuzzer, class TVUzzer>
std::unique_ptr<TFuzzer> BuildVUzzerFromArgs(
    FuzzerArgs &fuzzer_args, GlobalFuzzerOptions &global_options) {
  po::positional_options_description pargs_desc;
  pargs_desc.add("fuzzer", 1);
  pargs_desc.add("pargs", -1);

  VUzzerOptions vuzzer_options;

  po::options_description fuzzer_desc("VUzzer options");
  std::vector<std::string> pargs;
  fuzzer_desc.add_options()(
      "dict_file,x",
      po::value<std::vector<std::string>>(&vuzzer_options.dict_file)
          ->composing(),
      "Load additional dictionary file.")(
      "full_dict", po::value<std::string>(&vuzzer_options.full_dict),
      "Set path to \"full dictionary\". Default is `./full.dict`.")(
      "unique_dict", po::value<std::string>(&vuzzer_options.unique_dict),
      "Set path to \"unique dictionary\". Default is `./unique.dict`.")(
      "weight", po::value<std::string>(&vuzzer_options.weight),
      "Set path to \"weight file\". Default is `./weight`.")(
      "inst_bin", po::value<std::string>(&vuzzer_options.inst_bin),
      "Set path to instrumented binary. Default is `./instrumented.bin`.")(
      "taint_db", po::value<std::string>(&vuzzer_options.taint_db),
      "Set path to taint db. Default is `/mnt/polytracker/polytracker.db`.")(
      "taint_out", po::value<std::string>(&vuzzer_options.taint_out),
      "Set path to output for taint analysis. Default is `/tmp/taint.out`.")(
      "pargs", po::value<std::vector<std::string>>(&pargs),
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
    usage(fuzzer_args.global_options_description);
  }

  /* (Pin) Executor of vuzzer requires absolute path of PUT binary */
  pargs[0] = fs::absolute(pargs[0]).native();

  PutArgs put(pargs);
  try {
    put.Check();
  } catch (const exceptions::cli_error &e) {
    std::cerr << "[!] " << e.what() << std::endl;
    std::cerr << "\tat " << e.file << ":" << e.line << std::endl;
    usage(fuzzer_args.global_options_description);
  }

  DEBUG("[*] PUT: put = [");
  for (auto v : put.Args()) {
    DEBUG("\t\"%s\",", v.c_str());
  }
  DEBUG("    ]");

  using fuzzuf::algorithm::vuzzer::VUzzerSetting;
  using fuzzuf::algorithm::vuzzer::option::GetDefaultOutfile;
  using fuzzuf::algorithm::vuzzer::option::VUzzerTag;

  // Create VUzzerSetting
  std::shared_ptr<VUzzerSetting> setting(new VUzzerSetting(
      put.Args(), global_options.in_dir, global_options.out_dir,
      vuzzer_options.weight, vuzzer_options.full_dict,
      vuzzer_options.unique_dict, vuzzer_options.inst_bin,
      vuzzer_options.taint_db, vuzzer_options.taint_out, 0, 0));

  // PinToolExecutor needs the directory specified by "out_dir" to be already
  // set up so we need to create the directory first, and then initialize
  // Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  // XXX: VUzzer supports PinToolExecutor/PolyTrackerExecutor only. It does not
  // actually support `native` executor.
  if (global_options.executor != ExecutorKind::NATIVE) {
    EXIT("Unsupported executor: `%s`", global_options.executor.c_str());
  }

  // Create PinToolExecutor
  // FIXME: TEST_BINARY_DIR macro should be used only for test codes. We must
  // define a new macro in config.h.
  std::shared_ptr<fuzzuf::executor::PinToolExecutor> executor(
      new fuzzuf::executor::PinToolExecutor(
          FUZZUF_PIN_EXECUTABLE,
          {TEST_BINARY_DIR "/../tools/bbcounts2/bbcounts2.so", "-o", "bb.out",
           "-libc", "0"},
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->out_dir / GetDefaultOutfile()));

  // Create PolyTrackerExecutor
  std::shared_ptr<fuzzuf::executor::PolyTrackerExecutor> taint_executor(
      new fuzzuf::executor::PolyTrackerExecutor(
          TEST_BINARY_DIR "/../tools/polyexecutor/polyexecutor.py",
          setting->path_to_inst_bin, setting->path_to_taint_db,
          setting->path_to_taint_file, setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->out_dir / GetDefaultOutfile()));

  // Create VUzzerState
  using fuzzuf::algorithm::vuzzer::VUzzerState;

  auto state = std::make_unique<VUzzerState>(setting, executor, taint_executor);

  // Load dictionary
  for (const auto &d : vuzzer_options.dict_file) {
    using fuzzuf::algorithm::afl::dictionary::AFLDictData;

    const std::function<void(std::string &&)> f = [](std::string s) {
      ERROR("Dictionary error: %s", s.c_str());
    };

    fuzzuf::algorithm::afl::dictionary::load(d, state->extras, false, f);
  }
  fuzzuf::algorithm::afl::dictionary::SortDictByLength(state->extras);

  return std::unique_ptr<TFuzzer>(
      dynamic_cast<TFuzzer *>(new TVUzzer(std::move(state))));
}

}  // namespace fuzzuf::cli::fuzzer::vuzzer

#endif
