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
#define BOOST_TEST_MODULE algorithms.symcc.cli
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/utils/count_regular_files.hpp"
#include "fuzzuf/utils/filesystem.hpp"

BOOST_AUTO_TEST_CASE(ExecuteSymCCFromCLI) {
  // Setup root directory
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  FUZZUF_STANDARD_TEST_DIRS
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

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
                        "-e",
                        "native",
                        "--symcc_target",
                        TEST_BINARY_DIR "/put/symcc/symcc-easy_to_branch",
                        TEST_BINARY_DIR "/put/afl_gcc/afl_gcc-easy_to_branch",
                        nullptr};
  constexpr int argc = 11;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

  BOOST_TEST_CHECKPOINT("created fuzzer");

  fuzzer->OneLoop();

  std::size_t crash_count = 0u;
  for (const auto &e : fs::directory_iterator(output_dir / "crashes")) {
#ifdef HAS_CXX_STD_FILESYSTEM
    BOOST_CHECK(e.is_regular_file());
#else
    BOOST_CHECK(fs::is_regular_file(e.path()));
#endif
    ++crash_count;
  }
  // At least one crash input is produced
  BOOST_CHECK_GE(fuzzuf::utils::CountRegularFiles(output_dir / "crashes"), 1);

  BOOST_TEST_CHECKPOINT("done");
}
