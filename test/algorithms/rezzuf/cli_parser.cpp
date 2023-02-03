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

#include "fuzzuf/algorithms/rezzuf/rezzuf_state.hpp"
#define BOOST_TEST_MODULE algorithms.rezzuf.cli_parser
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/cli/fuzzer/rezzuf/build_rezzuf_fuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/cli/stub/afl_fuzzer_stub.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

BOOST_AUTO_TEST_CASE(BuildRezzufByParsingGlobalOptionAndPUT) {
  using RezzufState = fuzzuf::algorithm::rezzuf::RezzufState;
  using fuzzuf::executor::AFLExecutorInterface;
  fuzzuf::cli::GlobalFuzzerOptions options;
#pragma GCC diagnostic ignored "-Wwrite-strings"
  // 本来はschedule用のオプションもテストされるべきだが、CLI側の改修が必要なので一旦放置
  const char *argv[] = {
      "fuzzuf", "rezzuf",
      // Global options
      "--in_dir=chahz3ea4deRah4o", "--forksrv=false",
      // PUT options.
      // Because NativeLinuxExecutor throws error,
      // we can't use a random value here.
      "../put_binaries/command_wrapper",  // PUT
      "oung6UgoQue1eiYu"                  // arguments
  };
  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };

  // Parse global options and PUT, and build fuzzer
  using fuzzuf::cli::fuzzer::rezzuf::BuildRezzufFuzzerFromArgs;

  auto fuzzer_args = fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);
  auto fuzzer =
      BuildRezzufFuzzerFromArgs<fuzzuf::cli::AFLFuzzerStub<RezzufState>,
                                fuzzuf::cli::AFLFuzzerStub<RezzufState>,
                                AFLExecutorInterface>(fuzzer_args, options);

  BOOST_CHECK_EQUAL(options.in_dir, "chahz3ea4deRah4o");

  auto &state = *fuzzer->state;
  BOOST_CHECK_EQUAL(state.setting->argv.size(), 2);
  BOOST_CHECK_EQUAL(state.setting->argv[0], "../put_binaries/command_wrapper");
  BOOST_CHECK_EQUAL(state.setting->argv[1], "oung6UgoQue1eiYu");
}
