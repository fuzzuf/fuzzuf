#pragma once

#include "fuzzuf/algorithms/afl/afl_option.hpp"


namespace fuzzuf::algorithm::mopt { struct MOptTestcase; }
namespace fuzzuf::algorithm::mopt::option {

struct MOptTag {};

template<class Tag>
constexpr u32 GetSpliceCyclesUp(void) {
    return 25;
}

template<class Tag>
constexpr u32 GetSpliceCyclesLow(void) {
    return 5;
}

template<class Tag>
constexpr u32 GetPeriodPilot(void) {
    return 50000;
}

template<class Tag>
constexpr u32 GetPeriodCore(void) {
    return 500000;
}

} // namespace fuzzuf::algorithm::mopt::option
