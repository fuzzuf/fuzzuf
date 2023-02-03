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
#define BOOST_TEST_MODULE algorithms.ijon.cli
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/program_options.hpp>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <iostream>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/sha1.hpp"

namespace po = boost::program_options;

BOOST_AUTO_TEST_CASE(ExecuteIJONFromCLI) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";

  // Create input/output dirctory

  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  BOOST_TEST_CHECKPOINT("before init state");

  {
    // This input value is close to crash input so the crash input will be
    // discovered for small number of cycles
    std::vector<char> input{17, 0, 0, 0, 3, 4, 1, 0};
    auto initial_input_name = fuzzuf::utils::ToSerializedSha1(input);
    std::fstream fd((input_dir / initial_input_name).c_str(), std::ios::out);
    std::copy(input.begin(), input.end(), std::ostreambuf_iterator<char>(fd));
  }

  BOOST_TEST_CHECKPOINT("initialized dirs");

  const char *argv[] = {"fuzzuf",
                        "ijon",
                        "-i",
                        input_dir.c_str(),
                        "-o",
                        output_dir.c_str(),
                        "-e",
                        "forkserver",
                        TEST_BINARY_DIR "/put/ijon/ijon-test_put1",
                        nullptr};
  constexpr int argc = 9;
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
  BOOST_CHECK_GE(crash_count, 1);

  BOOST_TEST_CHECKPOINT("done");
}
