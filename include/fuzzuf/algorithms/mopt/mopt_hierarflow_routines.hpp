#pragma once

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"

#include <memory>

namespace fuzzuf::algorithm::mopt::routine {

namespace other {

using MOptMidCalleeRef = fuzzuf::algorithm::afl::routine::other::AFLMidCalleeRef<MOptState>;
using MOptMidInputType = fuzzuf::algorithm::afl::routine::other::AFLMidInputType<MOptState>;
using MOptMidOutputType = fuzzuf::algorithm::afl::routine::other::AFLMidOutputType<MOptState>;


struct MOptUpdate
    : public HierarFlowRoutine<
        MOptMidInputType,
        MOptMidOutputType
    > {
public:
    MOptUpdate(MOptState &state);

    MOptMidCalleeRef operator()(
        std::shared_ptr<MOptTestcase>
    );

private:
    MOptState &state;
};

struct CheckPacemakerThreshold
    : public HierarFlowRoutine<
        MOptMidInputType,
        MOptMidOutputType
    > {
public:
    CheckPacemakerThreshold(MOptState &state, MOptMidCalleeRef abandon_entry);

    MOptMidCalleeRef operator()(
        std::shared_ptr<MOptTestcase>
    );

private:
    MOptState &state;
};


} // namespace other


namespace mutation {

using MOptMutCalleeRef = fuzzuf::algorithm::afl::routine::mutation::AFLMutCalleeRef<MOptState>;
using fuzzuf::algorithm::afl::routine::mutation::HavocTemplate;
using fuzzuf::algorithm::afl::AFLMutatorTemplate;
using fuzzuf::algorithm::afl::routine::mutation::SplicingTemplate;
using fuzzuf::algorithm::afl::dictionary::AFLDictData;

struct MOptHavoc : public HavocTemplate<MOptState> {
public:
    MOptHavoc(MOptState &state);

    bool DoHavoc(
        AFLMutatorTemplate<MOptState>& mutator,
        optimizer::Optimizer<u32> &mutop_optimizer,
        void(*custom_cases)(u32, u8*&, u32&, const std::vector<AFLDictData>&, const std::vector<AFLDictData>&),
        const std::string &stage_name,
        const std::string &stage_short,
        u32 perf_score,
        s32 stage_max_multiplier, 
        int stage_idx
    );
};

struct Splicing : public SplicingTemplate<MOptState> {
public:
    Splicing(MOptState &state);

    MOptMutCalleeRef operator()(AFLMutatorTemplate<MOptState>& mutator) override;
};


} // namespace mutation

} // namespace fuzzuf::algorithm::mopt::routine