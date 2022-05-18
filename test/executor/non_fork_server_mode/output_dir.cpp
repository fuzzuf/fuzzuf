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
#define BOOST_TEST_MODULE native_linux_executor.non_fork_server_mode.output_dir
#define BOOST_TEST_DYN_LINK

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/vfs/read_once.hpp"

BOOST_AUTO_TEST_CASE(RetriveGeneratedFiles) {
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
  auto output_files_dir = root_dir / "output_files";

  // Create executor
  fuzzuf::executor::NativeLinuxExecutor executor(
      {TEST_BINARY_DIR "/executor/generate_outputs"}, 1000, 10000, false,
      path_to_write_seed, 0, 0, true,
      {std::string("OUTPUT_DIR=") + output_files_dir.string()}, {output_files_dir});

  // Run executor
  executor.Run(nullptr, 0);

  // The execution should success
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    PUTExitReasonType::FAULT_NONE);

  // Check if retrived files have valid content
  const std::map<fs::path, std::size_t> expected_data{
      {output_files_dir / "foo", std::hash<std::string>()("Hello, foo\n")},
      {output_files_dir / "bar", std::hash<std::string>()("Hello, bar\n")},
      {output_files_dir / "moo", std::hash<std::string>()("Hello, moo\n")}};
  std::map<fs::path, std::size_t> data;
  const auto files = ( executor.Filesystem()|fuzzuf::utils::vfs::adaptor::read_once ).MmapAll();
  std::transform(files.begin(), files.end(), std::inserter(data, data.end()),
                 [](const auto &v) {
                   return std::make_pair(
                       v.first, std::hash<std::string>()(std::string(
                                    v.second.begin(), v.second.end())));
                 });
  BOOST_CHECK_EQUAL(data.size(), expected_data.size());
  BOOST_CHECK(std::equal(data.begin(), data.end(), expected_data.begin(),
                         expected_data.end()));

  // Check if RemoveAll removes unretrived files.
  executor.Run(nullptr, 0);
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    PUTExitReasonType::FAULT_NONE);
  ( executor.Filesystem()|fuzzuf::utils::vfs::adaptor::read_once ).RemoveAll();
  executor.Run(nullptr, 0);
  // Since generate_outputs aborts if output files exist, it can be checked using exit status.
  BOOST_CHECK_EQUAL(executor.GetExitStatusFeedback().exit_reason,
                    PUTExitReasonType::FAULT_NONE);
}
