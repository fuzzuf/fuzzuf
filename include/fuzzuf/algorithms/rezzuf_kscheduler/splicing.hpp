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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_SPLICING_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_REZZUF_KSCHEDULER_SPLICING_HPP

#include <memory>
#include <cstdint>
#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/templates/afl_mutation_hierarflow_routines.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

struct Splicing
    : public afl::routine::mutation::HavocBaseTemplate<State> {
  using RezzufMutator = afl::AFLMutatorTemplate<State>;
 public:
  Splicing(State &state) :
    afl::routine::mutation::HavocBaseTemplate<State>(state) {}

  afl::routine::mutation::AFLMutCalleeRef<State> operator()(RezzufMutator &mutator);
};

}

#endif

