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

#ifndef FUZZUF_INCLUDE_ALGORITHM_AFLPLUSPLUS_AFLPLUSPLUS_MUTATION_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFLPLUSPLUS_AFLPLUSPLUS_MUTATION_HIERARFLOW_ROUTINES_HPP

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

using AFLplusplusState = aflplusplus::AFLplusplusState;

// explicit specialization
template <>
AFLMutCalleeRef<AFLplusplusState> HavocTemplate<AFLplusplusState>::operator()(
    AFLMutatorTemplate<AFLplusplusState>& mutator);

template <>
AFLMutCalleeRef<AFLplusplusState>
SplicingTemplate<AFLplusplusState>::operator()(
    AFLMutatorTemplate<AFLplusplusState>& mutator);

}  // namespace fuzzuf::algorithm::afl::routine::mutation

#endif
