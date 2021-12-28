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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_EXECUTE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_EXECUTE_HPP
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include <algorithm>
#include <cctype>
#include <iterator>
#include <type_traits>

namespace fuzzuf::algorithm::libfuzzer::executor {

/**
 * @fn
 * Run target with input, and acquire coverage,
 * outputs, execution result.
 *
 * @tparm Range Contiguous Range of std::uint8_t to pass input
 * @tparm Output Container of std::uint8_t to receive standard output
 * @tparm Cov Container of std::uint8_t to receive coverage
 * @tparm InputInfo Type of execution result
 * @tparm Executor executor type
 * @param state libFuzzer state object
 * @param corpus FullCorpus to add new execution result
 * @param range Input value that was passed to the executor
 * @param exec_result reference to execution result to output detail of this
 * execution
 * @param executor executor to run target
 * @param afl_coverage If True, coverage is retrived using GetAFLFeedback().
 * Otherwise coverage is retrived using GetBBFeedback().
 */
template <typename Range, typename Output, typename Cov, typename InputInfo,
          typename Executor>
auto Execute(Range &range, Output &output, Cov &cov, InputInfo &exec_result,
             Executor &executor, bool afl_coverage)
    -> std::enable_if_t<is_input_info_v<InputInfo> &&
                        utils::range::is_range_of_v<Range, std::uint8_t> &&
                        utils::range::has_data_v<Range> &&
                        utils::range::is_range_of_v<Output, std::uint8_t> &&
                        utils::range::is_range_of_v<Cov, std::uint8_t>> {
  const auto begin = std::chrono::high_resolution_clock::now();
  executor.Run(range.data(), fuzzuf::utils::range::rangeSize(range));
  const auto end = std::chrono::high_resolution_clock::now();
  exec_result.enabled = true;
  exec_result.time_of_unit =
      std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
  exec_result.status = executor.GetExitStatusFeedback().exit_reason;
  exec_result.signal = executor.GetExitStatusFeedback().signal;
  exec_result.added_to_corpus = false;
  exec_result.found_unique_features = 0u;
  if (afl_coverage) {
    executor.GetAFLFeedback().ShowMemoryToFunc([&](const u8 *head, u32 size) {
      cov.assign(head, std::next(head, size));
    });
  } else {
    executor.GetBBFeedback().ShowMemoryToFunc([&](const u8 *head, u32 size) {
      cov.assign(head, std::next(head, size));
    });
  }
  output = executor.MoveStdOut();
  auto err = executor.MoveStdErr();
  output.insert(output.end(), err.begin(), err.end());
}

} // namespace fuzzuf::algorithm::libfuzzer::executor

#endif
