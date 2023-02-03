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
#define BOOST_TEST_MODULE algorithms.aflplusplus.compute_weight
#define BOOST_TEST_DYN_LINK
#include <boost/test/tools/interface.hpp>
#include <boost/test/unit_test.hpp>
#include <random>

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_testcase.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_util.hpp"
#include "fuzzuf/cli/fuzzer/aflplusplus/build_aflplusplus_fuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/cli/stub/afl_fuzzer_stub.hpp"
#include "fuzzuf/executor/afl_executor_interface.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

BOOST_AUTO_TEST_CASE(ComputeWeightThenCompare) {
  using AFLplusplusState = fuzzuf::algorithm::aflplusplus::AFLplusplusState;
  using fuzzuf::executor::AFLExecutorInterface;
  fuzzuf::cli::GlobalFuzzerOptions options;
  // dummy argv
  const char *argv[] = {"fuzzuf",          "aflplusplus", "-i",     "/dev/null",
                        "--forksrv=false", "--",          "/bin/ls"};

  fuzzuf::cli::GlobalArgs args = {
      .argc = Argc(argv),
      .argv = argv,
  };

  // Parse global options and PUT, and build fuzzer
  using fuzzuf::cli::fuzzer::aflplusplus::BuildAFLplusplusFuzzerFromArgs;

  auto fuzzer_args = fuzzuf::cli::ParseGlobalOptionsForFuzzer(args, options);
  auto fuzzer = BuildAFLplusplusFuzzerFromArgs<
      fuzzuf::cli::AFLFuzzerStub<AFLplusplusState>,
      fuzzuf::cli::AFLFuzzerStub<AFLplusplusState>, AFLExecutorInterface>(
      fuzzer_args, options);

  auto &state = *fuzzer->state;

  const std::size_t count = 10;
  std::random_device gen;
  std::mt19937_64 engine(gen());

  // add dummy testcases
  for (std::size_t i = 0; i < count; ++i) {
    std::string devnull("/dev/null");
    const u8 buf[] = {'f', 'u', 'z', 'z'};
    u32 len = sizeof(buf);
    auto tc = state.AddToQueue(devnull, buf, len, false);
    // just fill the required elems with random values
    tc->exec_us = engine();
    tc->bitmap_size = static_cast<u32>(engine());
    tc->tc_ref = static_cast<u32>(engine());
  }
  BOOST_CHECK_EQUAL(count, state.case_queue.size());

  std::vector<double> vw1, vw2;
  fuzzuf::algorithm::aflplusplus::util::ComputeWeightVector(state, vw1);
  fuzzuf::algorithm::aflplusplus::util::ComputeWeightVector(state, vw2);

  BOOST_CHECK_EQUAL(vw1.size(), vw2.size());
  BOOST_TEST((vw1 == vw2), boost::test_tools::per_element());
}
