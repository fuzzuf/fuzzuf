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

#ifndef FUZZUF_INCLUDE_ALGORITHMS_REZZUF_REZZUF_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_REZZUF_REZZUF_HIERARFLOW_ROUTINES_HPP

#include <memory>

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_state.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_testcase.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::rezzuf::routine {

using afl::routine::mutation::AFLMutCalleeRef;
using afl::routine::other::AFLMidCalleeRef;
using afl::routine::other::AFLMidInputType;
using afl::routine::other::AFLMidOutputType;

using RezzufMutator = afl::AFLMutatorTemplate<RezzufState>;

struct RezzufSelectSeed
    : public hierarflow::HierarFlowRoutine<
          void(void), bool(std::shared_ptr<RezzufTestcase>)> {
 public:
  RezzufSelectSeed(RezzufState &state);

  utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>> operator()(void);

 private:
  RezzufState &state;
  u64 prev_queued = 0;
};

struct LoadSeedIfNeeded
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<RezzufState>,
                                           AFLMidOutputType<RezzufState>> {
 public:
  LoadSeedIfNeeded();

  AFLMidCalleeRef<RezzufState> operator()(std::shared_ptr<RezzufTestcase>);
};

struct RezzufApplyRandMuts
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<RezzufState>,
                                           AFLMidOutputType<RezzufState>> {
 public:
  RezzufApplyRandMuts(RezzufState &state,
                      AFLMidCalleeRef<RezzufState> abandon_entry);

  AFLMidCalleeRef<RezzufState> operator()(std::shared_ptr<RezzufTestcase>);

 private:
  RezzufState &state;
  AFLMidCalleeRef<RezzufState> abandon_entry;
};

struct RezzufHavoc
    : public afl::routine::mutation::HavocBaseTemplate<RezzufState> {
 public:
  RezzufHavoc(RezzufState &state);

  AFLMutCalleeRef<RezzufState> operator()(RezzufMutator &mutator);
};

struct RezzufSplicing
    : public afl::routine::mutation::HavocBaseTemplate<RezzufState> {
 public:
  RezzufSplicing(RezzufState &state);

  AFLMutCalleeRef<RezzufState> operator()(RezzufMutator &mutator);
};

struct RezzufAbandonEntry
    : public hierarflow::HierarFlowRoutine<AFLMidInputType<RezzufState>,
                                           AFLMidOutputType<RezzufState>> {
 public:
  RezzufAbandonEntry(RezzufState &state);

  AFLMidCalleeRef<RezzufState> operator()(std::shared_ptr<RezzufTestcase>);

 private:
  RezzufState &state;
};

}  // namespace fuzzuf::algorithm::rezzuf::routine

#endif
