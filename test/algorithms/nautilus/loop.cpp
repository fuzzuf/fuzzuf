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
#define BOOST_TEST_MODULE nautilus.loop
#define BOOST_TEST_DYN_LINK

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <move_to_program_location.hpp>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/fuzzer.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/option.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/setting.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

static void NautilusLoop(bool forksrv, size_t iter) {
  MoveToProgramLocation();

  /* Create root directory */
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);

  fs::path root_dir = fs::path(raw_dirname);

  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END;

  // Create input file
  fs::path put_dir = fs::path("../../put_binaries/nautilus");
  std::string output_dir = (root_dir / "output").string();
  std::vector<std::string> args{"../../put_binaries/nautilus/calc", "@@"};
  std::string path_to_grammar{"./calc_grammar.json"};

  std::cout << "    PUT: " << fs::absolute(put_dir) << std::endl;
  std::cout << "    Grammar: " << fs::absolute(path_to_grammar) << std::endl;

  using namespace fuzzuf::algorithm::nautilus::fuzzer;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::option;

  /* Create setting for Nautilus */
  std::shared_ptr<NautilusSetting> setting(new NautilusSetting(
      args, path_to_grammar, output_dir,
      fuzzuf::algorithm::afl::option::GetExecTimeout<NautilusTag>(),
      fuzzuf::algorithm::afl::option::GetMemLimit<NautilusTag>(), forksrv,
      fuzzuf::utils::CPUID_BIND_WHICHEVER,

      GetDefaultNumOfThreads(), GetDefaultThreadSize(),
      GetDefaultNumOfGenInputs(), GetDefaultNumOfDetMuts(),
      GetDefaultMaxTreeSize(), GetDefaultBitmapSize()));

  /* Craete output directories */
  std::vector<std::string> folders{"signaled", "queue", "timeout", "chunks"};
  for (auto f : folders) {
    fs::create_directories(fuzzuf::utils::StrPrintf(
        "%s/%s", setting->path_to_workdir.c_str(), f.c_str()));
  }

  using fuzzuf::algorithm::afl::option::GetDefaultOutfile;
  using fuzzuf::algorithm::afl::option::GetMapSize;
  using fuzzuf::executor::AFLExecutorInterface;

  /* Create NativeLinuxExecutor */
  auto nle = std::make_shared<fuzzuf::executor::NativeLinuxExecutor>(
      args, setting->exec_timeout_ms, setting->exec_memlimit, setting->forksrv,
      setting->path_to_workdir / GetDefaultOutfile<NautilusTag>(),
      GetMapSize<NautilusTag>(),  // afl_shm_size
      0,                          // bb_shm_size
      setting->cpuid_to_bind);

  auto executor = std::make_shared<AFLExecutorInterface>(std::move(nle));

  using fuzzuf::algorithm::nautilus::fuzzer::NautilusState;
  using fuzzuf::algorithm::nautilus::grammartec::ChunkStore;

  /* Create state for Nautilus */
  auto state = std::make_unique<NautilusState>(setting, executor);

  /* Create fuzzer instance */
  auto fuzzer = NautilusFuzzer(std::move(state));

  /* We run at least 2 loops to check both GenerateInput and ProcessInput
     0: Test SelectInput, GenerateInput, UpdateState
     1: Test ProcessInput, InitializeState
   */
  for (size_t i = 0; i < iter; i++) {
    std::cout << "the " << i << "-th iteration starts" << std::endl;
    fuzzer.OneLoop();
  }
}

BOOST_AUTO_TEST_CASE(NautilusLoopNonFork) {
  std::cout << "[*] NautilusLoopNonFork started\n";
  NautilusLoop(false, 2);
  std::cout << "[*] NautilusLoopNonFork ended\n";
}

BOOST_AUTO_TEST_CASE(NautilusLoopFork) {
  std::cout << "[*] NautilusLoopFork started\n";
  NautilusLoop(true, 20);
  std::cout << "[*] NautilusLoopFork ended\n";
}
