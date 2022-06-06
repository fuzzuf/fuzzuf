
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"

namespace fuzzuf::algorithm::afl::option {

template<>
u32 GetSpliceCycles<mopt::MOptTestcase>(AFLStateTemplate<mopt::MOptTestcase>& state) {
    return static_cast<mopt::MOptState>(state).splice_cycles_limit;
}

} // namespace fuzzuf::algorithm::afl::option

