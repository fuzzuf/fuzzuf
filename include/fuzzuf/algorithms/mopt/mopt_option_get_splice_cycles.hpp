#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"

// separated from mopt_option.hpp as methods defined here access MOptState member

namespace fuzzuf::algorithm::afl::option {

template<>
u32 GetSpliceCycles<mopt::MOptState>(mopt::MOptState& state) {
    return state.splice_cycles_limit;
}

} // namespace fuzzuf::algorithm::afl::option
