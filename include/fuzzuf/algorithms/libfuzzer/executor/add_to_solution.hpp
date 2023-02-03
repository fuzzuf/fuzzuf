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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_ADD_TO_SOLUTIONS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_EXECUTOR_ADD_TO_SOLUTIONS_HPP
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/corpus/add_to_solution.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/corpus.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/utils/filtered_range.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::libfuzzer::executor {

/**
 * @brief Insert execution result to solutions if the result is added to corpus
 * and target returned error status( any status excepting FAULT_NONE ) on exit.
 * @tparam Range Contiguous Range of std::uint8_t
 * @tparam InputInfo Type to provide execution result
 * @param range Input value that was passed to the executor
 * @param exec_result Execution result that was produced by the executor
 * @param crashed_only If false, all inputs that was added to corpus are added
 * to solutions. Otherwise, inputs that was added to corpus and returned error
 * status are added to solutions.
 * @params path_prefix Directory to output solutions.
 * @return Return true if the input is added to solutions. Otherwise, return
 * false.
 */
template <typename Range, typename InputInfo>
auto AddToSolution(Range &range, InputInfo &exec_result, bool crashed_only,
                   const fs::path &path_prefix)
    -> std::enable_if_t<is_input_info_v<InputInfo> &&
                            utils::range::is_range_of_v<Range, std::uint8_t> &&
                            utils::range::has_data_v<Range>,
                        bool> {
  if (exec_result.added_to_corpus &&
      (!crashed_only ||
       exec_result.status != feedback::PUTExitReasonType::FAULT_NONE)) {
    corpus::AddToSolution(range, exec_result, path_prefix);
    return true;
  }
  return false;
}

}  // namespace fuzzuf::algorithm::libfuzzer::executor

#endif
