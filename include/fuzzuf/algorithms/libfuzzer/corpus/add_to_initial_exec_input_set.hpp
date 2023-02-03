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
 * @file add_to_initial_exec_input_set.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_ADD_TO_INITIAL_INPUT_SET_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_CORPUS_ADD_TO_INITIAL_INPUT_SET_HPP
#include <cassert>
#include <type_traits>

#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/utils/range_traits.hpp"

namespace fuzzuf::algorithm::libfuzzer::corpus {

/**
 * Insert value to initial input value set.
 * For contiguous range
 *
 * @tparam Range Contiguous Range of std::uint8_t
 * @param initial_exec_input_set ExecInputSet to insert value
 * @param range Initial Input value to be inserted
 */
template <typename Range>
auto addToInitialExecInputSet(exec_input::ExecInputSet &initial_exec_input_set,
                              const Range &range)
    -> std::enable_if_t<utils::range::has_data_v<Range>> {
  assert(!utils::range::rangeEmpty(range));

  auto exec_input = initial_exec_input_set.CreateOnMemory(
      range.data(), utils::range::rangeSize(range));
  assert(exec_input);
}

/**
 * Insert value to initial input value set.
 * For non contiguous range
 *
 * @tparam Range Contiguous Range of std::uint8_t
 * @param initial_exec_input_set ExecInputSet to insert value
 * @param range Initial Input value to be inserted
 */
template <typename Range>
auto addToInitialExecInputSet(exec_input::ExecInputSet &initial_exec_input_set,
                              const Range &range)
    -> std::enable_if_t<!utils::range::has_data_v<Range>> {
  assert(!utils::range::rangeEmpty(range));
  std::vector<utils::range::RangeValueT<Range>> temp(range.begin(),
                                                     range.end());
  auto exec_input =
      initial_exec_input_set.CreateOnMemory(temp.data(), temp.size());
  assert(exec_input);
}

}  // namespace fuzzuf::algorithm::libfuzzer::corpus

#endif
