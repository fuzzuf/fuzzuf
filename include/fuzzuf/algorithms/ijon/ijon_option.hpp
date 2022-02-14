/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_OPTION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_OPTION_HPP

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"

namespace fuzzuf::algorithm::ijon { struct IJONState; }

namespace fuzzuf::algorithm::ijon::option {

struct IJONTag {};

template<class Tag>
constexpr u32 GetMaxMapSize(void) { 
    return 512;
}

} // namespace fuzzuf::algorithm::ijon::option

namespace fuzzuf::algorithm::afl::option {

template<>
constexpr const char* GetVersion<ijon::IJONState>(ijon::IJONState&) { 
    return "2.57b-ijon";
}

template<>
constexpr u32 GetHavocBlkSmall<ijon::option::IJONTag>(void) { 
    return 8;
}

template<>
constexpr u32 GetHavocBlkMedium<ijon::option::IJONTag>(void) { 
    return 32;
}

template<>
constexpr u32 GetHavocBlkLarge<ijon::option::IJONTag>(void) { 
    return 512;
}

template<>
constexpr u32 GetHavocBlkXl<ijon::option::IJONTag>(void) { 
    return 512;
}

template<>
constexpr u32 GetSpliceCycles<ijon::IJONState>(ijon::IJONState&) { 
    return 8;
}

// IJON uses `stage_max = SPLICE_HAVOC * perf_score / havoc_div / 200` in the splice stage
// instead of `SPLICE_HAVOC * perf_score / havoc_div / 100` for some reason.
// Therefore, we deal with this by dividing SPLICE_HAVOC(=32) by 2.
template<>
constexpr u32 GetSpliceHavoc<ijon::IJONState>(ijon::IJONState&) { 
    return 16;
}

} // namespace fuzzuf::algorithm::afl::option


#endif
