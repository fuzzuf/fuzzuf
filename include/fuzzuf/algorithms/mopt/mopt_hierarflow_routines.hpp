#pragma once

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