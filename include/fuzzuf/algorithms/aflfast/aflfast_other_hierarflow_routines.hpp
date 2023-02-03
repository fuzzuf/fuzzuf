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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_AFLFAST_AFLFAST_OTHER_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_AFLFAST_AFLFAST_OTHER_HIERARFLOW_ROUTINES_HPP

#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_testcase.hpp"

namespace fuzzuf::algorithm::afl::routine::other {

using AFLFastState = aflfast::AFLFastState;
using AFLFastTestcase = aflfast::AFLFastTestcase;

// explicit specialization
template <>
AFLMidCalleeRef<AFLFastState> ApplyDetMutsTemplate<AFLFastState>::operator()(
    std::shared_ptr<AFLFastTestcase> testcase);

// explicit specialization
template <>
AFLMidCalleeRef<AFLFastState> AbandonEntryTemplate<AFLFastState>::operator()(
    std::shared_ptr<AFLFastTestcase> testcase);

}  // namespace fuzzuf::algorithm::afl::routine::other
#endif
