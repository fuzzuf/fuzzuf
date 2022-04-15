#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"
#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"

#include <memory>

namespace fuzzuf::algorithm::mopt::routine {

namespace other {

using MOptMidCalleeRef = fuzzuf::algorithm::afl::routine::other::AFLMidCalleeRef<MOptState>;
using MOptMidInputType = fuzzuf::algorithm::afl::routine::other::AFLMidInputType<MOptState>;
using MOptMidOutputType = fuzzuf::algorithm::afl::routine::other::AFLMidOutputType<MOptState>;


struct AbandonEntryPuppet
    : public HierarFlowRoutine<
        MOptMidInputType,
        MOptMidOutputType
    > {
public:
    AbandonEntryPuppet(MOptState &state);

    MOptMidCalleeRef operator()(
        std::shared_ptr<MOptTestcase>
    );

private:
    MOptState &state;
}

struct ApplyDetMuts : public ApplyDetMutsTemplate<MOptState> {
public:
    ApplyDetMuts(
        MOptState &state,
        AFLMidCalleeRef<MOptState> abondon_entry
    );

    MOptMidCalleeRef operator()(
        std::shared_ptr<MOptTestcase>
    );
}

} // namespace other

} // namespace fuzzuf::algorithm::mopt::routine