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
#pragma once

#include <string>
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/count_classes.hpp"

namespace fuzzuf::algorithm::afl::util {
    
template<class Tag, class UInt>
UInt EFF_APOS(UInt p);

template<class Tag, class UInt>
UInt EFF_REM(UInt x);

template<class Tag, class UInt>
UInt EFF_ALEN(UInt l);

template<class Tag, class UInt>
UInt EFF_SPAN_ALEN(UInt p, UInt l);

u32 UR(u32 limit, int rand_fd);

std::string DescribeInteger(u64 val);
std::string DescribeFloat(double val);
std::string DescribeMemorySize(u64 val);
std::string DescribeTimeDelta(u64 cur_ms, u64 event_ms);

template<class UInt>
void ClassifyCounts(UInt *mem, u32 map_size);

template<class UInt>
void SimplifyTrace(UInt *mem, u32 map_size);

u32 HavocCaseDistrib(
    const std::vector<dictionary::AFLDictData>& extras,
    const std::vector<dictionary::AFLDictData>& a_extras
);

} // namespace fuzzuf::algorithm::afl::util

// Define template functions
namespace fuzzuf::algorithm::afl::util {

template<class Tag, class UInt>
UInt EFF_APOS(UInt p) {
    return p >> option::GetEffMapScale2<Tag>();
}

template<class Tag, class UInt>
UInt EFF_REM(UInt x) {
    return x & ((UInt(1) << option::GetEffMapScale2<Tag>()) - 1);
}

template<class Tag, class UInt>
UInt EFF_ALEN(UInt l) {
    return EFF_APOS<Tag>(l) + !!EFF_REM<Tag>(l);
}

template<class Tag, class UInt>
UInt EFF_SPAN_ALEN(UInt p, UInt l) {
    return EFF_APOS<Tag>(p + l - 1) - EFF_APOS<Tag>(p) + 1;
}

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static constexpr std::array<u8, 256> InitCountClass8() {
    std::array<u8, 256> count_class_lookup8 {};

    count_class_lookup8[0] = 0;
    count_class_lookup8[1] = 1;
    count_class_lookup8[2] = 2;
    count_class_lookup8[3] = 4;
    for (int i=4;   i<8;   i++) count_class_lookup8[i] = 8;
    for (int i=8;   i<16;  i++) count_class_lookup8[i] = 16;
    for (int i=16;  i<32;  i++) count_class_lookup8[i] = 32;
    for (int i=32;  i<128; i++) count_class_lookup8[i] = 64;
    for (int i=128; i<256; i++) count_class_lookup8[i] = 128;
    return count_class_lookup8;
}

static constexpr std::array<u16, 65536> InitCountClass16(
    const std::array<u8, 256>& count_class_lookup8
) {
    std::array<u16, 65536> count_class_lookup16 {};

    for (int b1 = 0; b1 < 256; b1++) {
        for (int b2 = 0; b2 < 256; b2++) {
            count_class_lookup16[(b1 << 8) + b2] =
                (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];
        }
    }

    return count_class_lookup16;
}

static constexpr CountClasses InitCountClasses() {
    auto count_class_lookup8  = InitCountClass8();
    auto count_class_lookup16 = InitCountClass16(count_class_lookup8);
    return CountClasses{ count_class_lookup8, count_class_lookup16 };
}

// Make sure InitCountClasses() is really a constexpr function:
// static_assert throws error if InitCountClasses() cannot be evaluated at compile time.
static_assert(
       true
    // We are not interested in the latter condition.
    // This condition is just for evaluating InitCountClasses() at compile time.
    // Regardless of this condition, static_assert should be true.
    || InitCountClasses().lookup16[0] == 0
);

template<class UInt>
void ClassifyCounts(UInt *mem, u32 map_size) {
    constexpr CountClasses count_class = InitCountClasses();

    constexpr unsigned int width = sizeof(UInt);
    static_assert(width == 4 || width == 8);

    int wlog;
    if constexpr (width == 4) {
      wlog = 2;
    } else if constexpr (width == 8) {
      wlog = 3;
    }

    u32 i = map_size >> wlog;
    while (i--) {
        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem)) {
            u16* mem16 = (u16*)mem;

            for (unsigned int j=0; j*sizeof(u16) < width; j++) {
                mem16[j] = count_class.lookup16[mem16[j]];
            }
        }

        mem++;
    }
}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

template<class UInt>
void SimplifyTrace(UInt *mem, u32 map_size) {
    static std::vector<u8> simplify_lookup(256, 128);
    simplify_lookup[0] = 1;

    constexpr int width = sizeof(UInt);

    int wlog;
    UInt val_not_found;
    if constexpr (width == 4) {
        wlog = 2;
        val_not_found = 0x01010101;
    } else if constexpr (width == 8) {
        wlog = 3;
        val_not_found = 0x0101010101010101;
    }
    
    u32 i = map_size >> wlog;
    while (i--) {
        /* Optimize for sparse bitmaps. */
        
        if (unlikely(*mem)) {
            u8* mem8 = (u8*)mem;
            for (int j=0; j<width; j++) {
                mem8[j] = simplify_lookup[mem8[j]];
            }
        } else *mem = val_not_found;

        mem++;
    }
}

} // namespace fuzzuf::algorithm::afl::util
