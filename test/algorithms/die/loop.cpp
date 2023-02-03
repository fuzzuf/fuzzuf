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
#define BOOST_TEST_MODULE die.loop
#define BOOST_TEST_DYN_LINK

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <move_to_program_location.hpp>

#include "config.h"
#include "fuzzuf/algorithms/die/die_fuzzer.hpp"
#include "fuzzuf/algorithms/die/die_option.hpp"
#include "fuzzuf/algorithms/die/die_setting.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/workspace.hpp"

BOOST_AUTO_TEST_CASE(DIELoop) {
  std::cout << "[*] DIELoop started\n";

  // cd $(dirname $0)
  MoveToProgramLocation();

  /* Create root directory */
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);

  auto root_dir = fs::path(raw_dirname);

  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END;

  /* Create input file */
  fs::path put_dir = fs::path("../../put_binaries/quickjs/");

  /* Copy seeds because jsi and type files are generate in this directory */
  fs::copy(put_dir / "seeds", root_dir / "seeds");

  fs::path input_dir = root_dir / "seeds";
  fs::path output_dir = root_dir / "output";

  using namespace fuzzuf::algorithm::afl;
  using fuzzuf::algorithm::die::DIEFuzzer;
  using fuzzuf::algorithm::die::DIESetting;
  using fuzzuf::algorithm::die::DIEState;
  using fuzzuf::algorithm::die::option::DIETag;
  using fuzzuf::executor::AFLExecutorInterface;
  namespace dieoption = fuzzuf::algorithm::die::option;

  fs::path path_put = put_dir / "qjs";
  std::shared_ptr<DIESetting> setting(new DIESetting(
      {path_put.string(), "@@"},  // argv
      input_dir.native(),         // in_dir
      output_dir.native(),        // out_dir
      option::GetExecTimeout<DIETag>(), option::GetMemLimit<DIETag>(),
      true,   // forksrv
      false,  // dump_mode
      fuzzuf::utils::CPUID_BIND_WHICHEVER,
      "../../../tools/die/DIE",       // die_dir
      "python3", "node",              // cmd_py, cmd_node
      path_put.string(), "",          // d8_path, d8_flags
      "../../../tools/die/typer.py",  // typer_path
      100                             // mut_cnt
      ));

  // NativeLinuxExecutor needs the directory specified by "out_dir" to be
  // already set up so we need to create the directory first, and then
  // initialize Executor
  fuzzuf::utils::SetupDirs(setting->out_dir.string());

  // Create NativeLinuxExecutor
  auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
      setting->argv, setting->exec_timelimit_ms, setting->exec_memlimit,
      setting->forksrv, setting->out_dir / option::GetDefaultOutfile<DIETag>(),
      option::GetMapSize<DIETag>(),  // afl_shm_size
      0                              // bb_shm_size
  );

  auto executor = std::make_shared<AFLExecutorInterface>(std::move(nle));

  // Create DIEState
  auto state = std::make_unique<DIEState>(setting, executor);

  DIEFuzzer fuzzer(std::move(state));

  for (int i = 0; i < 1; i++) {
    std::cout << "The " << i << "-th iteration starts" << std::endl;
    fuzzer.OneLoop();
  }

  std::cout << "[*] DIELoop ended\n";
}
