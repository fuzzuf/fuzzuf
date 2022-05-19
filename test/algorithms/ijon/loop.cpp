/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#define BOOST_TEST_MODULE ijon.loop
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <random>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_fuzzer.hpp"
#include "fuzzuf/algorithms/ijon/ijon_havoc.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_state.hpp"
#include "fuzzuf/algorithms/ijon/shared_data.hpp"
#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/executor/ijon_executor_interface.hpp"
#include "fuzzuf/executor/linux_fork_server_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "move_to_program_location.hpp"


// to test both fork server mode and non fork server mode, we specify forksrv
// via an argument
static void IJONLoop(/* bool forksrv */) {
  namespace afl = fuzzuf::algorithm::afl;
  namespace ijon = fuzzuf::algorithm::ijon;

  // cd $(dirname $0)
  MoveToProgramLocation();

  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname)
    throw -1;
  BOOST_CHECK(raw_dirname != nullptr);

  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END

  auto put_dir = fs::path("../../put_binaries/libjpeg");
  const std::vector<std::string> put_args = {"/home/aoki/atla/fuzzuf-cc/put/ijon/ijon-test"};

  // Build fuzzer
  using ijon::option::IJONTag;
  using afl::AFLSetting;
  using afl::option::GetExecTimeout;
  using afl::option::GetMemLimit;
  using afl::option::GetDefaultOutfile;
  auto setting = std::make_shared<const AFLSetting>(
                      // {TEST_SOURCE_DIR "put_binaries/ijon-test"},
                      put_args,
                      put_dir / "seeds",
                      root_dir / "output",
                      GetExecTimeout<IJONTag>(),
                      GetMemLimit<IJONTag>(),
                      /* forkserv */ true,
                      /* dumb_mode */ false,  // FIXME: add dumb_mode
                      Util::CPUID_BIND_WHICHEVER
                  );
  SetupDirs(setting->out_dir.string());
  auto executor = std::make_shared<fuzzuf::executor::IJONExecutorInterface>(
      std::make_shared<LinuxForkServerExecutor>(
        setting->argv,
        setting->exec_timelimit_ms,
        setting->exec_memlimit,
        setting->out_dir / GetDefaultOutfile<IJONTag>(),
        afl::option::GetMapSize<ijon::option::IJONTag>(), // afl_shm_size
        0, // bb_shm_size
        sizeof(ijon::SharedData) // extra_shm_size
      )
  );

  // One shot execution
  executor->Run((u8 *) "AAAABBBB", 8);
  InplaceMemoryFeedback feedback = executor->GetIJONFeedback();
  feedback.ShowMemoryToFunc(
    [](const u8* shared_data, u32 /* map_size */) {
      {
        // Check if ijon_area is not blank
        auto count = Util::CountBytes(
          (u8 *) ((ijon::SharedData *) shared_data)->afl_area,
          afl::option::GetMapSize<ijon::option::IJONTag>()
        );
        std::cout << "[*] afl_area has " << count << " non-zero bytes" << std::endl;
        BOOST_CHECK_NE(count, 0);
      }

      {
        // Check if afl_max is not blank
        auto count = Util::CountBytes(
          (u8 *) ((ijon::SharedData *) shared_data)->afl_max,
          sizeof(u64) * ijon::option::GetMaxMapSize<ijon::option::IJONTag>()
        );
        std::cout << "[*] afl_max has " << count << " non-zero bytes" << std::endl;
        BOOST_CHECK_NE(count, 0);
      }
    }
  );
  exit(1);

  auto mutop_optimizer = std::unique_ptr<fuzzuf::optimizer::Optimizer<u32>>(
                            new ijon::havoc::IJONHavocCaseDistrib()
                          );
  auto state = std::make_unique<ijon::IJONState>(
                  setting,
                  executor,
                  std::move(mutop_optimizer)
                );
  auto fuzzer = ijon::IJONFuzzer(std::move(state));

  // Fuzzing loop
  for (int i = 0; i < 1; i++) {
    std::cout << "the " << i << "-th iteration starts" << std::endl;
    fuzzer.OneLoop();
  }
}

// Non-forkserver mode is not supported by LinuxForkServerExecutor as of now
// BOOST_AUTO_TEST_CASE(IJONLoopNonForkMode) {
//   std::cout << "[*] IJONLoopNonForkMode started\n";
//   IJONLoop(false);
//   std::cout << "[*] IJONLoopNonForkMode ended\n";
// }

BOOST_AUTO_TEST_CASE(IJONLoopForkMode) {
  std::cout << "[*] IJONLoopForkMode started\n";
  IJONLoop(/* true */);
  std::cout << "[*] IJONLoopForkMode ended\n";
}
