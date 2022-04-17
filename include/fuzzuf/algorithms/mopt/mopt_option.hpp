#pragma once

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"

namespace fuzzuf::algorithm::mopt::option {

struct MOptTag {};

namespace fuzzuf::algorithm::mopt::option {

template<Tag>
constexpr u32 GetSpliceCyclesUp(void) {
    return 25;
}

template<Tag>
constexpr u32 GetSpliceCyclesLow(void) {
    return 5;
}

}

} // namespace fuzzuf::algorithm::mopt::option

namespace fuzzuf::algorithm::afl::option {

template<>
constexpr u32 GetSpliceCycles<mopt::MOptTestcase>(AFLStateTemplate<mopt::MOptTestcase>& state) {
    return (mopt::MOptState&)state->splice_cycles;
}


} // namespace fuzzuf::algorithm::afl::option
