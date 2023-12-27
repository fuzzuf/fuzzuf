/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_APPLY_RAND_MUTS_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_APPLY_RAND_MUTS_HPP

#include <memory>
#include <cstdint>
#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

struct ApplyRandMuts
    : public hierarflow::HierarFlowRoutine<afl::routine::other::AFLMidInputType<State>,
                                           afl::routine::other::AFLMidOutputType<State>> {
 public:
  ApplyRandMuts(State &state,
                      afl::routine::other::AFLMidCalleeRef<State> abandon_entry) : state( state ), abandon_entry( abandon_entry ) {}

  afl::routine::other::AFLMidCalleeRef<State> operator()(std::shared_ptr<Testcase>);

 private:
  State &state;
  afl::routine::other::AFLMidCalleeRef<State> abandon_entry;
};

}

#endif

