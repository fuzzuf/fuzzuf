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
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"
#define BOOST_TEST_MODULE algorithms.aflplusplus.fast3_score
#define BOOST_TEST_DYN_LINK
#include <boost/test/tools/interface.hpp>
#include <boost/test/unit_test.hpp>

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_testcase.hpp"
#include "fuzzuf/cli/fuzzer/aflplusplus/build_aflplusplus_fuzzer_from_args.hpp"
#include "fuzzuf/cli/global_args.hpp"
#include "fuzzuf/cli/global_fuzzer_options.hpp"
#include "fuzzuf/cli/parse_global_options_for_fuzzer.hpp"
#include "fuzzuf/cli/stub/afl_fuzzer_stub.hpp"
#include "fuzzuf/executor/afl_executor_interface.hpp"

#define Argc(argv) (sizeof(argv) / sizeof(char *))

BOOST_AUTO_TEST_CASE(CalcScoresForEachPowerScheds) {
  using AFLplusplusState = fuzzuf::algorithm::aflplusplus::AFLplusplusState;
  using fuzzuf::executor::AFLExecutorInterface;
  fuzzuf::cli::GlobalFuzzerOptions options;
  // dummy argv
  const char *argv[] = {"fuzzuf", "aflplusplus",     "-i", "/dev/null", "-p",
                        "fast",   "--forksrv=false", "--", "/bin/ls"};
  std::vector<std::pair<const char *, u32>> schedules = {
      {"fast", 60}, {"coe", 0},    {"explore", 30},
      {"lin", 35},  {"quad", 705}, {"exploit", 960},
  };

  for (auto &sched : schedules) {
    // ugly, but it works
    argv[5] = sched.first;
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

    // set dummy state member variables (to avoid div by zero, and fix
    // perf_score to 10*3 = 30) in this test, perf_score will be fixed to 30
    state.total_cal_cycles = 1;
    state.total_bitmap_entries = 1;

    // add a dummy testcase 1
    // set up member variables to make return values different by each power
    // schedule
    std::string devnull("/dev/null");
    const u8 buf[] = {'f', 'u', 'z', 'z'};
    u32 len = sizeof(buf);
    auto tc1 = state.AddToQueue(devnull, buf, len, false);
    tc1->exec_us = 1;
    tc1->bitmap_size = 1;
    tc1->fuzz_level = 20;
    tc1->n_fuzz_entry = 0;
    tc1->favored = false;
    state.n_fuzz[tc1->n_fuzz_entry] = 16;  // log2(16) = 4

    // add a dummy testcase 2 (unused for score calculation)
    auto tc2 = state.AddToQueue(devnull, buf, len, false);
    tc2->n_fuzz_entry = 1;
    state.n_fuzz[tc2->n_fuzz_entry] = 1;  // log2(1) = 0

    u32 score = state.DoCalcScore(*tc1);
    std::cout << sched.first << ": " << score << std::endl;
    BOOST_CHECK_EQUAL(score, sched.second);
  }
}
