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
 * @file loop.cpp
 * @brief Test code for VUzzers loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#define BOOST_TEST_MODULE VUzzer.loop
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <move_to_program_location.hpp>
#include <random>

#include "config.h"
#include "fuzzuf/algorithms/vuzzer/vuzzer.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/workspace.hpp"

// to test both fork server mode and non fork server mode, we specify forksrv
// via an argument
static void VUzzerLoop() {
  // cd $(dirname $0)
  MoveToProgramLocation();

  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);

  auto root_dir = fs::path(raw_dirname);

  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END

  // Create input file
  auto put_dir = fs::path("../../put_binaries/calc");
  auto input_dir = put_dir / "seeds";
  auto output_dir = root_dir / "output";

  using namespace fuzzuf::algorithm::vuzzer;
  using fuzzuf::algorithm::vuzzer::option::GetDefaultOutfile;
  using fuzzuf::algorithm::vuzzer::option::VUzzerTag;

  std::shared_ptr<VUzzerSetting> setting(new VUzzerSetting(
      {"../../put_binaries/calc/calc", "@@"}, input_dir.native(),
      output_dir.native(), "../../put_binaries/calc/calc.weight",
      "../../put_binaries/calc/calc_full.dict",
      "../../put_binaries/calc/calc_unique.dict",
      "../../put_binaries/calc/calc.instrumented", "/tmp/polytracker.db",
      "/tmp/taint.out", 0, 0));

  // PinToolExecutor needs the directory specified by "out_dir" to be already
  // set up so we need to create the directory first, and then initialize
  // Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  // TODO: support more types of executors
  // FIXME: TEST_BINARY_DIR macro should be used only for test codes. We must
  // define a new macro in config.h.
  std::shared_ptr<fuzzuf::executor::PinToolExecutor> executor(
      new fuzzuf::executor::PinToolExecutor(
          FUZZUF_PIN_EXECUTABLE,
          {TEST_BINARY_DIR "/../tools/bbcounts2/bbcounts2.so", "-o", "bb.out",
           "-libc", "0"},
          setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->out_dir / GetDefaultOutfile()));

  std::shared_ptr<fuzzuf::executor::PolyTrackerExecutor> taint_executor(
      new fuzzuf::executor::PolyTrackerExecutor(
          TEST_BINARY_DIR "/../tools/polyexecutor/polyexecutor.py",
          setting->path_to_inst_bin, setting->path_to_taint_db,
          setting->path_to_taint_file, setting->argv,
          setting->exec_timelimit_ms, setting->exec_memlimit,
          setting->out_dir / GetDefaultOutfile()));

  // Create VUzzerState
  std::unique_ptr<VUzzerState> state(
      new VUzzerState(setting, executor, taint_executor));

  // Create fuzzer instance
  auto fuzzer = VUzzer(std::move(state));

  for (int i = 0; i < 1; i++) {
    std::cout << "the " << i << "-th iteration starts" << std::endl;
    fuzzer.OneLoop();
  }
}

BOOST_AUTO_TEST_CASE(VUzzerLoopNonFork) {
  std::cout << "[*] VUzzerLoop started\n";
  VUzzerLoop();
  std::cout << "[*] VUzzerLoop ended\n";
}
