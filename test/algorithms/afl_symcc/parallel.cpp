/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
#define BOOST_TEST_MODULE algorithms.symcc.parallel
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>
#include <fstream>
#include <iostream>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/utils/count_regular_files.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"

BOOST_AUTO_TEST_CASE(ExecuteSymCCWithParallel) {
  // Setup root directory
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_STANDARD_TEST_DIRS
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  FUZZUF_SETUP_EXTERNAL_QUEUE

  BOOST_TEST_CHECKPOINT("before init state");

  {
    // This input value is close to crash input so the crash input will be
    // discovered for small number of cycles
    std::vector<char> input{17, 0, 0, 0, 3, 4, 1, 0};
    FUZZUF_SETUP_SINGLE_INITIAL_INPUT(input)
  }

  BOOST_TEST_CHECKPOINT("initialized dirs");
  const char *argv[] = {"fuzzuf",
                        "afl_symcc",
                        "-i",
                        input_dir.c_str(),
                        "-o",
                        output_dir.c_str(),
                        "-M",
                        "fuzzer0",
                        "--symcc_target",
                        TEST_BINARY_DIR "/put/symcc/symcc-hard_to_branch",
                        TEST_BINARY_DIR "/put/afl_gcc/afl_gcc-hard_to_branch",
                        nullptr};
  constexpr int argc = 11;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

  BOOST_TEST_CHECKPOINT("created fuzzer");

  // Minimum required cycles to invoke synchronization
  for (size_t i = 0u; i != 2u; ++i) {
    fuzzer->OneLoop();
  }

  // At least one crash input is produced
  BOOST_CHECK_GE(
      fuzzuf::utils::CountRegularFiles(output_dir / "fuzzer0" / "crashes"), 1);

  BOOST_TEST_CHECKPOINT("done");
}

BOOST_AUTO_TEST_CASE(ExecuteSymCCWithoutParallel) {
  // Setup root directory
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_STANDARD_TEST_DIRS
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  // No external queue setup
  BOOST_TEST_CHECKPOINT("before init state");

  {
    // This input value is close to crash input so the crash input will be
    // discovered for small number of cycles
    std::vector<char> input{17, 0, 0, 0, 3, 4, 1, 0};
    FUZZUF_SETUP_SINGLE_INITIAL_INPUT(input)
  }

  BOOST_TEST_CHECKPOINT("initialized dirs");
  const char *argv[] = {"fuzzuf",
                        "afl_symcc",
                        "-i",
                        input_dir.c_str(),
                        "-o",
                        output_dir.c_str(),
                        "-M",
                        "fuzzer0",
                        "--symcc_target",
                        TEST_BINARY_DIR "/put/symcc/symcc-hard_to_branch",
                        TEST_BINARY_DIR "/put/afl_gcc/afl_gcc-hard_to_branch",
                        nullptr};
  constexpr int argc = 11;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

  BOOST_TEST_CHECKPOINT("created fuzzer");

  // Minimum required cycles to invoke synchronization
  for (size_t i = 0u; i != 2u; ++i) {
    fuzzer->OneLoop();
  }
  
  // AFL+SymCC cannot find the crash path
  BOOST_CHECK_EQUAL(
      fuzzuf::utils::CountRegularFiles(output_dir / "fuzzer0" / "crashes"), 0);

  BOOST_TEST_CHECKPOINT("done");
}
