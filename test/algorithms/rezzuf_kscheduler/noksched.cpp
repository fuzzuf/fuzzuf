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
#define BOOST_TEST_MODULE algorithms.rezzuf_kscheduler.noksched
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <boost/test/unit_test.hpp>

#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/utils/count_regular_files.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/kscheduler/gen_dyn_weight.hpp"
#include "fuzzuf/utils/copy.hpp"

BOOST_AUTO_TEST_CASE(ExecuteAFLKSchedulerFromNoKSched) {
  // Setup root directory
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto* const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);

//  FUZZUF_STANDARD_TEST_DIRS
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions)

  BOOST_TEST_CHECKPOINT("before init state");

  fs::current_path( root_dir );

  for( const auto &e: fs::directory_iterator( fs::path( TEST_SOURCE_DIR )/"put"/"kscheduler"/"harfbuzz"/"harfbuzz"/"test"/"shaping"/"fonts"/"sha1sum" ) ) {
    fuzzuf::utils::copy( e.path(), input_dir );
  }

  BOOST_TEST_CHECKPOINT("initialized dirs");

  const char *argv[] = {"fuzzuf",
                        "rezzuf",
                        "-i",
                        input_dir.c_str(),
                        "-o",
                        output_dir.c_str(),
			"--forksrv",
			"false",
                        TEST_BINARY_DIR "/put/kscheduler/harfbuzz/kscheduler-harfbuzz",
			"@@",
                        nullptr};
  constexpr int argc = 10;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);

  BOOST_TEST_CHECKPOINT("created fuzzer");

  //for( int i = 0; i != 10; ++i )
  while( 1 )
    fuzzer->OneLoop();

  // At least one crash input is produced
  BOOST_CHECK_GE(fuzzuf::utils::CountRegularFiles(output_dir / "crashes"), 1);

  BOOST_TEST_CHECKPOINT("done");
}
