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
#define BOOST_TEST_MODULE algorithms.afl.partial_cli
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
  const char *argv[] = {"fuzzuf", "libfuzzer", "--target",
                        TEST_BINARY_DIR "/put/afl-gcc/afl-empty", nullptr};
  // const char *argv[] = {"fuzzuf", "afl",
  //                      TEST_BINARY_DIR "/put/afl-gcc/afl-empty", nullptr};
  constexpr int argc = 4;
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv(argc, argv);
}
