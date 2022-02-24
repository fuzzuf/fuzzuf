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

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl {

template<class Testcase> struct AFLStateTemplate;

} // namespace fuzzuf::algorithm::afl 

namespace fuzzuf::algorithm::afl::option {

// The following enumerators cannot be "enum class" 
// because they are used to index arrays

/* Stage value types */

enum StageVal {
    STAGE_VAL_NONE = 0,
    STAGE_VAL_LE   = 1,
    STAGE_VAL_BE   = 2
};

enum StageIndex {
    STAGE_FLIP1       =  0,
    STAGE_FLIP2       =  1,
    STAGE_FLIP4       =  2,
    STAGE_FLIP8       =  3,
    STAGE_FLIP16      =  4,
    STAGE_FLIP32      =  5,
    STAGE_ARITH8      =  6,
    STAGE_ARITH16     =  7,
    STAGE_ARITH32     =  8,
    STAGE_INTEREST8   =  9,
    STAGE_INTEREST16  = 10,
    STAGE_INTEREST32  = 11,
    STAGE_EXTRAS_UO   = 12,
    STAGE_EXTRAS_UI   = 13,
    STAGE_EXTRAS_AO   = 14,
    STAGE_HAVOC       = 15,
    STAGE_SPLICE      = 16
};

// The following constants are provided as constexpr getters.
// Those getters are always defined as one of two types of template functions:
// 1. a template function that receives an (AFL)State instance as a sole argument. 
// 2. a template function that receives no argument, but must be specialized by (AFL)Tag.
//
// Defining them this way allows us to easily change the values of constants.
// If you want to do that, you can just use template specialization with DerivedState or DerivedTag.
// You can even trasform these constants into dynamic values if needed because 
// constexpr functions behave as normal functions when they cannot be evaluated at compile time.

struct AFLTag {};

template<class Testcase>
constexpr const char* GetVersion(AFLStateTemplate<Testcase>&) { 
    return "2.57b";
}

// NOTE: this function cannot have the argument
// because this is used in afl::util.

template<class Tag>
constexpr u32 GetReseedRng(void) { 
    return 10000;
}

// NOTE: this function cannot have the argument
// because this is used in the declaration of member variables.

template<class Tag>
constexpr u32 GetExecTimeout(void) { 
    return 1000;
}

// NOTE: this function cannot have the argument
// because this is used outside AFL.
// In 32-bit environments, MEM_LIMIT = 50.
// In 64-bit environments, MEM_LIMIT = 25.
template<class Tag>
constexpr u32 GetMemLimit(void) { 
    static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8);

    if constexpr (sizeof(size_t) == 4) {
        return 50;
    } else {
        return 25;
    }
}

template<class Testcase>
constexpr u32 GetCalCycles(AFLStateTemplate<Testcase>&) { 
    return 8;
}

template<class Testcase>
constexpr u32 GetCalCyclesLong(AFLStateTemplate<Testcase>&) { 
    return 40;
}

/* Number of subsequent timeouts before abandoning an input file: */
template<class Testcase>
constexpr u32 GetTmoutLimit(AFLStateTemplate<Testcase>&) { 
    return 250;
}

/* Maximum number of unique hangs or crashes to record: */
template<class Testcase>
constexpr u32 GetKeepUniqueHang(AFLStateTemplate<Testcase>&) { 
    return 500;
}

template<class Testcase>
constexpr u32 GetKeepUniqueCrash(AFLStateTemplate<Testcase>&) { 
    return 5000;
}

/* Baseline number of random tweaks during a single 'havoc' stage: */
template<class Testcase>
constexpr u32 GetHavocCycles(AFLStateTemplate<Testcase>&) { 
    return 256;
}

template<class Testcase>
constexpr u32 GetHavocCyclesInit(AFLStateTemplate<Testcase>&) { 
    return 1024;
}

/* Maximum multiplier for the above (should be a power of two, beware
    of 32-bit int overflows): */
template<class Testcase>
constexpr u32 GetHavocMaxMult(AFLStateTemplate<Testcase>&) { 
    return 16;
}

/* Absolute minimum number of havoc cycles (after all adjustments): */
template<class Testcase>
constexpr s32 GetHavocMin(AFLStateTemplate<Testcase>&) { 
    return 16;
}
    
/* Maximum stacking for havoc-stage tweaks. The actual value is calculated
    like this: 

    n = random between 1 and HAVOC_STACK_POW2
    stacking = 2^n

    In other words, the default (n = 7) produces 2, 4, 8, 16, 32, 64, or
    128 stacked tweaks: */

template<class Testcase>
constexpr u32 GetHavocStackPow2(AFLStateTemplate<Testcase>&) { 
    return 7;
}

/* Caps on block sizes for cloning and deletion operations. Each of these
    ranges has a 33% probability of getting picked, except for the first
  two cycles where smaller blocks are favored: */

// NOTE: these functions cannot have the argument
// because these are used in Mutator.
// If you want to refer to State in these functions,
// probably we need to have also GetHavocBlkSmall(AFLStateTemplate<Testcase>&).

template<class Tag>
constexpr u32 GetHavocBlkSmall(void) { 
    return 32;
}

template<class Tag>
constexpr u32 GetHavocBlkMedium(void) { 
    return 128;
}

template<class Tag>
constexpr u32 GetHavocBlkLarge(void) { 
    return 1500;
}

/* Extra-large blocks, selected very rarely (<5% of the time): */

template<class Tag>
constexpr u32 GetHavocBlkXl(void) { 
    return 32768;
}

/* Calibration timeout adjustments, to be a bit more generous when resuming
    fuzzing sessions or trying to calibrate already-added internal finds.
    The first value is a percentage, the other is in milliseconds: */

template<class Testcase>
constexpr u32 GetCalTmoutPerc(AFLStateTemplate<Testcase>&) { 
    return 125;
}

template<class Testcase>
constexpr u32 GetCalTmoutAdd(AFLStateTemplate<Testcase>&) { 
    return 50;
}

/* Number of chances to calibrate a case before giving up: */

template<class Testcase>
constexpr u32 GetCalChances(AFLStateTemplate<Testcase>&) { 
    return 3;
}
    
// NOTE: this function cannot have the argument
// because this is used in GetMapSize.

template<class Tag>
constexpr u32 GetMapSizePow2(void) { 
    return 16;
}

// NOTE: this function cannot have the argument
// because this is used in the declaration of member variables.

template<class Tag>
constexpr u32 GetMapSize(void) { 
    return 1 << GetMapSizePow2<Tag>();
}

template<class Testcase>
constexpr u32 GetStatusUpdateFreq(AFLStateTemplate<Testcase>&) { 
    return 1;
}

// NOTE: this function cannot have the argument
// because this is used outside AFL.
// Maybe we can move this to NativeLinuxExecutor?

template<class Tag>
constexpr const char* GetDefaultOutfile(void) { 
    return ".cur_input";
}

template<class Testcase>
constexpr const char* GetClangEnvVar(AFLStateTemplate<Testcase>&) { 
    return "__AFL_CLANG_MODE";
}

template<class Testcase>
constexpr const char* GetAsLoopEnvVar(AFLStateTemplate<Testcase>&) { 
    return "__AFL_AS_LOOPCHECK";
}

template<class Testcase>
constexpr const char* GetPersistEnvVar(AFLStateTemplate<Testcase>&) { 
    return "__AFL_PERSISTENT";
}

template<class Testcase>
constexpr const char* GetDeferEnvVar(AFLStateTemplate<Testcase>&) { 
    return "__AFL_DEFER_FORKSRV";
}

/* ...when there are new, pending favorites */
template<class Testcase>
constexpr u32 GetSkipToNewProb(AFLStateTemplate<Testcase>&) { 
    return 99;
}

/* ...no new favs, cur entry already fuzzed */
template<class Testcase>
constexpr u32 GetSkipNfavOldProb(AFLStateTemplate<Testcase>&) { 
    return 95;
}

/* ...no new favs, cur entry not fuzzed yet */
template<class Testcase>
constexpr u32 GetSkipNfavNewProb(AFLStateTemplate<Testcase>&) { 
    return 75;
}

/* Splicing cycle count: */
template<class Testcase>
constexpr u32 GetSpliceCycles(AFLStateTemplate<Testcase>&) { 
    return 15;
}

/* Nominal per-splice havoc cycle length: */
template<class Testcase>
constexpr u32 GetSpliceHavoc(AFLStateTemplate<Testcase>&) { 
    return 32;
}

/* Maximum offset for integer addition / subtraction stages: */

// NOTE: this function cannot have the argument
// because this is used in Mutator.

template<class Tag>
constexpr u32 GetArithMax(void) { 
    return 35;
}

/* Maximum size of input file, in bytes (keep under 100MB): */

// NOTE: this function cannot have the argument
// because this is used in Mutator.

template<class Tag>
constexpr u32 GetMaxFile(void) { 
    return 1 * 1024 * 1024;
}

/* The same, for the test case minimizer: */
template<class Testcase>
constexpr u32 GetTminMaxFile(AFLStateTemplate<Testcase>&) { 
    return 10 * 1024 * 1024;
}

/* Block normalization steps for afl-tmin: */
template<class Testcase>
constexpr u32 GetTminSetMinSize(AFLStateTemplate<Testcase>&) { 
    return 4;
}

template<class Testcase>
constexpr u32 GetTminSetSteps(AFLStateTemplate<Testcase>&) { 
    return 128;
}

/* Maximum dictionary token size (-x), in bytes: */
template<class Testcase>
constexpr u32 GetMaxDictFile(AFLStateTemplate<Testcase>&) { 
    return 128;
}

/* Length limits for auto-detected dictionary tokens: */
template<class Testcase>
constexpr u32 GetMinAutoExtra(AFLStateTemplate<Testcase>&) { 
    return 3;
}

template<class Testcase>
constexpr u32 GetMaxAutoExtra(AFLStateTemplate<Testcase>&) { 
    return 32;
}

/* Maximum number of user-specified dictionary tokens to use in deterministic
    steps; past this point, the "extras/user" step will be still carried out,
    but with proportionally lower odds: */
template<class Testcase>
constexpr u32 GetMaxDetExtras(AFLStateTemplate<Testcase>&) { 
    return 200;
}

/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
    (first value), and to keep in memory as candidates. The latter should be much
    higher than the former. */
template<class Testcase>
constexpr u32 GetUseAutoExtras(AFLStateTemplate<Testcase>&) { 
    return 50;
}

template<class Testcase>
constexpr u32 GetMaxAutoExtras(AFLStateTemplate<Testcase>& state) { 
    return GetUseAutoExtras(state) * 10;
}

/* Scaling factor for the effector map used to skip some of the more
    expensive deterministic steps. The actual divisor is set to
    2^EFF_MAP_SCALE2 bytes: */

// NOTE: this function cannot have the argument
// because this is used in afl::util.

template<class Testcase>
constexpr u32 GetEffMapScale2(void) { 
    return 3;
}

/* Minimum input file length at which the effector logic kicks in: */
template<class Testcase>
constexpr u32 GetEffMinLen(AFLStateTemplate<Testcase>&) { 
    return 128;
}

/* Maximum effector density past which everything is just fuzzed
    unconditionally (%): */
template<class Testcase>
constexpr u32 GetEffMaxPerc(AFLStateTemplate<Testcase>&) { 
    return 90;
}

/* UI refresh frequency (Hz): */
template<class Testcase>
constexpr u32 GetUiTargetHz(AFLStateTemplate<Testcase>&) { 
    return 5;
}

/* Fuzzer stats file and plot update intervals (sec): */
template<class Testcase>
constexpr u32 GetStatsUpdateSec(AFLStateTemplate<Testcase>&) { 
    return 60;
}

template<class Testcase>
constexpr u32 GetPlotUpdateSec(AFLStateTemplate<Testcase>&) { 
    return 60;
}

/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */
template<class Testcase>
constexpr u32 GetAvgSmoothing(AFLStateTemplate<Testcase>&) { 
    return 16;
}
    
/* Limits for the test case trimmer. The absolute minimum chunk size; and
    the starting and ending divisors for chopping up the input file: */
template<class Testcase>
constexpr u32 GetTrimMinBytes(AFLStateTemplate<Testcase>&) { 
    return 4;
}

template<class Testcase>
constexpr u32 GetTrimStartSteps(AFLStateTemplate<Testcase>&) { 
    return 16;
}

template<class Testcase>
constexpr u32 GetTrimEndSteps(AFLStateTemplate<Testcase>&) { 
    return 1024;
}
    
/* A made-up hashing seed: */

// NOTE: this function cannot have the argument
// because this is used in Feedbacks.

template<class Tag>
constexpr u32 GetHashConst(void) { 
    return 0xa5b35705;
}
    
} // namespace fuzzuf::algorithm::afl::option
