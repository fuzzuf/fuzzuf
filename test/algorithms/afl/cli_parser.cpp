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
#define BOOST_TEST_MODULE algorithms.afl.cli_parser
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/cli/fuzzer/afl/build_afl_fuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/cli/stub/afl_fuzzer_stub.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

fuzzuf::cli::GlobalFuzzerOptions default_options;  // Default value goes here

BOOST_AUTO_TEST_CASE(BuildAFLByParsingGlobalOptionAndPUT) {
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {
      "fuzzuf", "afl",
      // Global options
      "--in_dir=gS53LCfbAhunlziS", "--forksrv=false",
      // PUT options.
      // Because NativeLinuxExecutor throws error,
      // we can't use a random value here.
      "../put_binaries/command_wrapper",  // PUT
      "Jpx1kB6oh8N9wUe0"                  // arguments
  };
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };

  using AFLState = fuzzuf::algorithm::afl::AFLState;
  using fuzzuf::cli::fuzzer::afl::BuildAFLFuzzerFromArgs;
  using fuzzuf::executor::AFLExecutorInterface;

  // Parse global options and PUT, and build fuzzer
  auto fuzzer_args = fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);
  auto fuzzer =
      BuildAFLFuzzerFromArgs<fuzzuf::cli::AFLFuzzerStub<AFLState>,
                             fuzzuf::cli::AFLFuzzerStub<AFLState>,
                             AFLExecutorInterface>(fuzzer_args, options);

  BOOST_CHECK_EQUAL(options.in_dir, "gS53LCfbAhunlziS");

  auto &state = *fuzzer->state;
  BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
  BOOST_CHECK_EQUAL(state.setting->argv[0], "../put_binaries/command_wrapper");
  BOOST_CHECK_EQUAL(state.setting->argv[1], "Jpx1kB6oh8N9wUe0");
}

BOOST_AUTO_TEST_CASE(BuildAFLByParsingGlobalOptionAndFuzzerOptionAndPUT) {
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  const char *argv[] = {
      "fuzzuf", "afl",
      // Global options
      "--in_dir=u4I8Vq8mMTaCE5CH", "--forksrv=false",
      // Fuzzer options
      "--dict_file=" TEST_DICTIONARY_DIR "/test.dict",
      // PUT options.
      // Because NativeLinuxExecutor throws error,
      // we can't use a random value here.
      "../put_binaries/command_wrapper",  // PUT
      "f996ko6rvPgSajvm"                  // arguments
  };
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };

  using AFLState = fuzzuf::algorithm::afl::AFLState;
  using fuzzuf::cli::fuzzer::afl::BuildAFLFuzzerFromArgs;
  using fuzzuf::executor::AFLExecutorInterface;

  // Parse global options and PUT, and build fuzzer
  auto fuzzer_args = fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);
  auto fuzzer =
      BuildAFLFuzzerFromArgs<fuzzuf::cli::AFLFuzzerStub<AFLState>,
                             fuzzuf::cli::AFLFuzzerStub<AFLState>,
                             AFLExecutorInterface>(fuzzer_args, options);

  // Check if global option is captured correctly
  BOOST_CHECK_EQUAL(options.in_dir, "u4I8Vq8mMTaCE5CH");

  auto &state = *fuzzer->state;

  // Check if fuzzer option (dict_file) is captured correctly, and dict file has
  // been loaded
  BOOST_CHECK_EQUAL(state.extras.size(), 3);

  // Check if PUT args are captured correctly
  BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
  BOOST_CHECK_EQUAL(state.setting->argv[0], "../put_binaries/command_wrapper");
  BOOST_CHECK_EQUAL(state.setting->argv[1], "f996ko6rvPgSajvm");
}
