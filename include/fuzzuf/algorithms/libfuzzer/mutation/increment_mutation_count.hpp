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
 * @file increment_mutation_count.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_INCREMENT_MUTATIONS_COUNT_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_INCREMENT_MUTATIONS_COUNT_HPP
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/state/input_info.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"

namespace fuzzuf::algorithm::libfuzzer::mutator {

template <typename State, typename InputInfo>
auto IncrementMutationsCount(State &state, InputInfo &exec_result)
    -> std::enable_if_t<is_state_v<State> && is_input_info_v<InputInfo>> {
  ++state.executed_mutations_count;
  ++exec_result.executed_mutations_count;
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator

#endif
