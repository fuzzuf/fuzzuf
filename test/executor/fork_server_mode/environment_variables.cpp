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
#define BOOST_TEST_MODULE                                                      \
  native_linux_executor.fork_server_mode.environment_variables
#define BOOST_TEST_DYN_LINK

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/filesystem.hpp"

BOOST_AUTO_TEST_CASE(NativeLinuxExecutorWithEnvironmentVariables) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);
  auto path_to_write_seed = output_dir / "cur_input";

  // Create executor
  fuzzuf::executor::NativeLinuxExecutor executor({TEST_BINARY_DIR "/put_binaries/command_wrapper",
                                TEST_BINARY_DIR "/executor/print_env", "@@"},
                               1000, 10000, true, path_to_write_seed, 0, 0,
                               true, {"FOO=World"});

  // Run executor
  executor.Run(nullptr, 0);

  // The execution should success due to the required environment variable is
  // set
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    PUTExitReasonType::FAULT_NONE);

  // Check if appropriate value is set on the environment variable
  const auto standard_output = executor.MoveStdOut();
  const auto expected_output = std::string("World\n");
  BOOST_CHECK_EQUAL_COLLECTIONS(standard_output.begin(), standard_output.end(),
                                expected_output.begin(), expected_output.end());
}

BOOST_AUTO_TEST_CASE(NativeLinuxExecutorWithoutEnvironmentVariables) {
  // Setup root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto *const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) { fs::remove_all(root_dir); }
  BOOST_SCOPE_EXIT_END
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);
  auto path_to_write_seed = output_dir / "cur_input";

  // Create executor
  fuzzuf::executor::NativeLinuxExecutor executor({TEST_BINARY_DIR "/put_binaries/command_wrapper",
                                TEST_BINARY_DIR "/executor/print_env", "@@"},
                               1000, 10000, true, path_to_write_seed, 0, 0,
                               true);

  // Run executor
  executor.Run(nullptr, 0);

  // The execution should fail due to the required environment variable is not
  // set
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    PUTExitReasonType::FAULT_CRASH);
}
