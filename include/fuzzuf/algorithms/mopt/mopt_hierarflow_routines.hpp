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

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_HIERARFLOW_ROUTINES_HPP

#include <memory>

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::mopt::routine {

namespace other {

using MOptMidCalleeRef =
    fuzzuf::algorithm::afl::routine::other::AFLMidCalleeRef<MOptState>;
using MOptMidInputType =
    fuzzuf::algorithm::afl::routine::other::AFLMidInputType<MOptState>;
using MOptMidOutputType =
    fuzzuf::algorithm::afl::routine::other::AFLMidOutputType<MOptState>;
using fuzzuf::hierarflow::HierarFlowRoutine;

struct MOptUpdate
    : public HierarFlowRoutine<MOptMidInputType, MOptMidOutputType> {
 public:
  MOptUpdate(MOptState &state);

  MOptMidCalleeRef operator()(std::shared_ptr<MOptTestcase>);

 private:
  MOptState &state;
};

struct CheckPacemakerThreshold
    : public HierarFlowRoutine<MOptMidInputType, MOptMidOutputType> {
 public:
  CheckPacemakerThreshold(MOptState &state, MOptMidCalleeRef abandon_entry);

  MOptMidCalleeRef operator()(std::shared_ptr<MOptTestcase>);

 private:
  MOptState &state;
  MOptMidCalleeRef abandon_entry;
};

struct SavePacemakerHitCnt
    : public HierarFlowRoutine<MOptMidInputType, MOptMidOutputType> {
 public:
  SavePacemakerHitCnt(MOptState &state);

  MOptMidCalleeRef operator()(std::shared_ptr<MOptTestcase>);

 private:
  MOptState &state;
};

}  // namespace other

namespace mutation {

using MOptMutCalleeRef =
    fuzzuf::algorithm::afl::routine::mutation::AFLMutCalleeRef<MOptState>;
using MOptMutator = fuzzuf::algorithm::afl::AFLMutatorTemplate<MOptState>;
using fuzzuf::algorithm::afl::routine::mutation::HavocBaseTemplate;
using fuzzuf::algorithm::afl::routine::mutation::HavocTemplate;
using fuzzuf::algorithm::afl::routine::mutation::SplicingTemplate;

struct MOptHavoc : public HavocBaseTemplate<MOptState> {
 public:
  MOptHavoc(MOptState &state);
  MOptMutCalleeRef operator()(MOptMutator &mutator) override;
};

struct MOptSplicing : public HavocBaseTemplate<MOptState> {
 public:
  MOptSplicing(MOptState &state);
  MOptMutCalleeRef operator()(MOptMutator &mutator) override;
};

}  // namespace mutation

}  // namespace fuzzuf::algorithm::mopt::routine

#endif
