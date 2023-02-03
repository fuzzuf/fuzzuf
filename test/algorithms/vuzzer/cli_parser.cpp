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
#define BOOST_TEST_MODULE algorithms.vuzzer.cli_parser
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/cli/fuzzer/vuzzer/build_vuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/cli/stub/vuzzer_stub.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

BOOST_AUTO_TEST_CASE(BuildVUzzerByParsingGlobalOptionAndPUT) {
  using VUzzerState = fuzzuf::algorithm::vuzzer::VUzzerState;
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"

  const char *argv[] = {
      "fuzzuf", "vuzzer",
      // Global options
      "--in_dir=1yGosmSge1Fb4pNA", "--weight=db05iKsZORKkxela",
      "--full_dict=SNqUXXzGJqyE78SC", "--unique_dict=lz025YtrYx3hLoYO",
      "--inst_bin=BSAGFocvr8wPERXK", "--taint_db=dKiBtlnutZAUczkS",
      "--taint_out=a85cZxCSaxkpewYb", "--",
      // PUT options.
      // Because NativeLinuxExecutor throws error,
      // we can't use a random value here.
      "../put_binaries/command_wrapper",  // PUT
      "HQ5lspLelPJPEC35"                  // arguments
  };
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };

  // Parse global options and PUT, and build fuzzer
  using fuzzuf::cli::fuzzer::vuzzer::BuildVUzzerFromArgs;

  auto fuzzer_args = fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);
  auto fuzzer = BuildVUzzerFromArgs<fuzzuf::cli::VUzzerStub<VUzzerState>,
                                    fuzzuf::cli::VUzzerStub<VUzzerState>>(
      fuzzer_args, options);

  BOOST_CHECK_EQUAL(options.in_dir, "1yGosmSge1Fb4pNA");

  auto &state = *fuzzer->state;

  BOOST_CHECK_EQUAL(state.setting->path_to_weight_file, "db05iKsZORKkxela");
  BOOST_CHECK_EQUAL(state.setting->path_to_full_dict, "SNqUXXzGJqyE78SC");
  BOOST_CHECK_EQUAL(state.setting->path_to_unique_dict, "lz025YtrYx3hLoYO");
  BOOST_CHECK_EQUAL(state.setting->path_to_inst_bin, "BSAGFocvr8wPERXK");
  BOOST_CHECK_EQUAL(state.setting->path_to_taint_db, "dKiBtlnutZAUczkS");
  BOOST_CHECK_EQUAL(state.setting->path_to_taint_file, "a85cZxCSaxkpewYb");

  BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
  BOOST_CHECK_EQUAL(state.setting->argv[0],
                    fs::absolute("../put_binaries/command_wrapper")
                        .native());  // VUzzer converts PUTs path to abs path.
  BOOST_CHECK_EQUAL(state.setting->argv[1], "HQ5lspLelPJPEC35");
}
