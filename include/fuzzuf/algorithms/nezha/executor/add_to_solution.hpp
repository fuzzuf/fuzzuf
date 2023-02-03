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
/**
 * @file add_to_solution.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_ADD_TO_SOLUTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_ADD_TO_SOLUTION_HPP
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_solution.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/nezha/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/to_string.hpp"

namespace fuzzuf::algorithm::nezha::executor {

/**
 * @brief Insert execution result to solutions if the tuple of outputs is novel
 * or only part of coverage tuple contain novel features and at least two
 * targets produced diferent standard output.
 * @tparam Range Contiguous Range of std::uint8_t
 * @tparam Output Range of std::uint8_t
 * @param range Input value that was passed to the executor
 * @param exec_result Execution result that was produced by the executor
 * @param trace Range of bool that indicates execution result on each targets
 * that had been added to corpus.
 * @param trace_hash Previously appeared value of trace
 * @param outputs Range of hash value of standard output
 * @param outputs_hash Previously appeared value of outputs
 * @param path_prefix Directory to output solutions.
 * @return Return true if the input is added to solutions. Otherwise, return
 * false.
 */
template <typename Range, typename Output>
auto AddToSolution(Range &range, libfuzzer::InputInfo &exec_result,
                   const trace_t &trace, known_traces_t &trace_hash,
                   const Output &outputs, known_outputs_t &outputs_hash,
                   const fs::path &path_prefix)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t> &&
                            utils::range::has_data_v<Range>,
                        bool> {
  const auto new_outputs = outputs_hash.emplace(outputs).second;
  const auto new_coverage = trace_hash.emplace(trace).second;
  if (new_outputs || new_coverage) {
    std::string name = "diff_";
    std::unordered_set<std::uint64_t> unique;
    for (auto v : outputs) {
      unique.insert(v);
      utils::toStringADL(name, v);
      name += '_';
    }
    if (unique.size() >= 2u) {
      exec_result.name = std::move(name);
      libfuzzer::corpus::AddToSolution(range, exec_result, path_prefix);
    }
    return true;
  }
  return false;
}

/**
 * @brief Insert execution result to solutions if the tuple of status code is
 * novel or only part of coverage tuple contain novel features and only part of
 * targets exited as success( status code = 0 ).
 *
 * Corresponding code of original Nezha implementation
 * https://github.com/nezha-dt/nezha/blob/master/Fuzzer/FuzzerLoop.cpp#L165
 *
 * @tparam Range Contiguous Range of std::uint8_t
 * @tparam Output Range of std::uint8_t
 * @param range Input value that was passed to the executor
 * @param exec_result Execution result that was produced by the executor
 * @param trace Range of bool that indicates execution result on each targets
 * that had been added to corpus.
 * @param trace_hash Previously appeared value of trace
 * @param status Range of status code
 * @param status_hash Previously appeared value of status
 * @params path_prefix Directory to output solutions.
 * @return Return true if the input is added to solutions. Otherwise, return
 * false.
 */
template <typename Range>
auto AddToSolution(Range &range, libfuzzer::InputInfo &exec_result,
                   const trace_t &trace, known_traces_t &trace_hash,
                   const status_t &status, known_status_t &status_hash,
                   const fs::path &path_prefix)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t> &&
                            utils::range::has_data_v<Range>,
                        bool> {
  const auto new_status = status_hash.emplace(status).second;
  const auto new_coverage = trace_hash.emplace(trace).second;
  if (new_status || new_coverage) {
    std::string name = "diff_";
    bool has_zero = false;
    bool has_nonzero = false;
    for (auto v : status) {
      if (v == feedback::PUTExitReasonType::FAULT_NONE)
        has_zero = true;
      else
        has_nonzero = true;
      utils::toStringADL(name, int(v));
      name += '_';
    }
    if (has_zero && has_nonzero) {
      exec_result.name = std::move(name);
      libfuzzer::corpus::AddToSolution(range, exec_result, path_prefix);
    }
    return true;
  }
  return false;
}

}  // namespace fuzzuf::algorithm::nezha::executor

#endif
