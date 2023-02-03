/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
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

template <class State>
struct AFLStateTemplate;

}  // namespace fuzzuf::algorithm::afl

namespace fuzzuf::algorithm::afl::option {

// The following enumerators cannot be "enum class"
// because they are used to index arrays

/* Stage value types */

enum StageVal { STAGE_VAL_NONE = 0, STAGE_VAL_LE = 1, STAGE_VAL_BE = 2 };

enum StageIndex {
  STAGE_FLIP1 = 0,
  STAGE_FLIP2 = 1,
  STAGE_FLIP4 = 2,
  STAGE_FLIP8 = 3,
  STAGE_FLIP16 = 4,
  STAGE_FLIP32 = 5,
  STAGE_ARITH8 = 6,
  STAGE_ARITH16 = 7,
  STAGE_ARITH32 = 8,
  STAGE_INTEREST8 = 9,
  STAGE_INTEREST16 = 10,
  STAGE_INTEREST32 = 11,
  STAGE_EXTRAS_UO = 12,
  STAGE_EXTRAS_UI = 13,
  STAGE_EXTRAS_AO = 14,
  STAGE_HAVOC = 15,
  STAGE_SPLICE = 16
};

// The following constants are provided as constexpr getters.
// Those getters are always defined as one of two types of template functions:
// 1. a template function that receives an (AFL)State instance as a sole
// argument.
// 2. a template function that receives no argument, but must be specialized by
// (AFL)Tag.
//
// Defining them this way allows us to easily change the values of constants.
// If you want to do that, you can just use template specialization with
// DerivedState or DerivedTag. You can even trasform these constants into
// dynamic values if needed because constexpr functions behave as normal
// functions when they cannot be evaluated at compile time.

struct AFLTag {};

template <class State>
constexpr const char* GetVersion(State&) {
  return "2.57b";
}

// NOTE: this function cannot have the argument
// because this is used in afl::util.

template <class Tag>
constexpr u32 GetReseedRng(void) {
  return 10000;
}

// NOTE: this function cannot have the argument
// because this is used in the declaration of member variables.

template <class Tag>
constexpr u32 GetExecTimeout(void) {
  return 1000;
}

// NOTE: this function cannot have the argument
// because this is used outside AFL.
template <class Tag>
constexpr u32 GetMemLimit(void) {
  // Unlimited by default.
  return 0;
}

template <class State>
constexpr u32 GetCalCycles(State&) {
  return 8;
}

template <class State>
constexpr u32 GetCalCyclesLong(State&) {
  return 40;
}

/* Number of subsequent timeouts before abandoning an input file: */
template <class State>
constexpr u32 GetTmoutLimit(State&) {
  return 250;
}

/* Maximum number of unique hangs or crashes to record: */
template <class State>
constexpr u32 GetKeepUniqueHang(State&) {
  return 500;
}

template <class State>
constexpr u32 GetKeepUniqueCrash(State&) {
  return 5000;
}

/* Baseline number of random tweaks during a single 'havoc' stage: */
template <class State>
constexpr u32 GetHavocCycles(State&) {
  return 256;
}

template <class State>
constexpr u32 GetHavocCyclesInit(State&) {
  return 1024;
}

/* Maximum multiplier for the above (should be a power of two, beware
    of 32-bit int overflows): */
template <class State>
constexpr u32 GetHavocMaxMult(State&) {
  return 16;
}

/* Absolute minimum number of havoc cycles (after all adjustments): */
template <class State>
constexpr s32 GetHavocMin(State&) {
  return 16;
}

/* Maximum stacking for havoc-stage tweaks. The actual value is calculated
    like this:

    n = random between 1 and HAVOC_STACK_POW2
    stacking = 2^n

    In other words, the default (n = 7) produces 2, 4, 8, 16, 32, 64, or
    128 stacked tweaks: */

// NOTE: this function cannot have the argument
// because this is used outside AFL.
template <class Tag>
constexpr u32 GetHavocStackPow2(void) {
  return 7;
}

/* Caps on block sizes for cloning and deletion operations. Each of these
    ranges has a 33% probability of getting picked, except for the first
  two cycles where smaller blocks are favored: */

// NOTE: these functions cannot have the argument
// because these are used in Mutator.
// If you want to refer to State in these functions,
// probably we need to have also GetHavocBlkSmall(State&).

template <class Tag>
constexpr u32 GetHavocBlkSmall(void) {
  return 32;
}

template <class Tag>
constexpr u32 GetHavocBlkMedium(void) {
  return 128;
}

template <class Tag>
constexpr u32 GetHavocBlkLarge(void) {
  return 1500;
}

/* Extra-large blocks, selected very rarely (<5% of the time): */

template <class Tag>
constexpr u32 GetHavocBlkXl(void) {
  return 32768;
}

/* Calibration timeout adjustments, to be a bit more generous when resuming
    fuzzing sessions or trying to calibrate already-added internal finds.
    The first value is a percentage, the other is in milliseconds: */

template <class State>
constexpr u32 GetCalTmoutPerc(State&) {
  return 125;
}

template <class State>
constexpr u32 GetCalTmoutAdd(State&) {
  return 50;
}

/* Number of chances to calibrate a case before giving up: */

template <class State>
constexpr u32 GetCalChances(State&) {
  return 3;
}

// NOTE: this function cannot have the argument
// because this is used in GetMapSize.

template <class Tag>
constexpr u32 GetMapSizePow2(void) {
  return 16;
}

// NOTE: this function cannot have the argument
// because this is used in the declaration of member variables.

template <class Tag>
constexpr u32 GetMapSize(void) {
  return 1 << GetMapSizePow2<Tag>();
}

template <class State>
constexpr u32 GetStatusUpdateFreq(State&) {
  return 1;
}

// NOTE: this function cannot have the argument
// because this is used outside AFL.
// Maybe we can move this to NativeLinuxExecutor?

template <class Tag>
constexpr const char* GetDefaultOutfile(void) {
  return ".cur_input";
}

template <class State>
constexpr const char* GetClangEnvVar(State&) {
  return "__AFL_CLANG_MODE";
}

template <class State>
constexpr const char* GetAsLoopEnvVar(State&) {
  return "__AFL_AS_LOOPCHECK";
}

template <class State>
constexpr const char* GetPersistEnvVar(State&) {
  return "__AFL_PERSISTENT";
}

template <class State>
constexpr const char* GetDeferEnvVar(State&) {
  return "__AFL_DEFER_FORKSRV";
}

/* ...when there are new, pending favorites */
template <class State>
constexpr u32 GetSkipToNewProb(State&) {
  return 99;
}

/* ...no new favs, cur entry already fuzzed */
template <class State>
constexpr u32 GetSkipNfavOldProb(State&) {
  return 95;
}

/* ...no new favs, cur entry not fuzzed yet */
template <class State>
constexpr u32 GetSkipNfavNewProb(State&) {
  return 75;
}

/* Splicing cycle count: */
template <class State>
constexpr u32 GetSpliceCycles(State&) {
  return 15;
}

/* Nominal per-splice havoc cycle length: */
template <class State>
constexpr u32 GetSpliceHavoc(State&) {
  return 32;
}

/* Maximum offset for integer addition / subtraction stages: */

// NOTE: this function cannot have the argument
// because this is used in Mutator.

template <class Tag>
constexpr u32 GetArithMax(void) {
  return 35;
}

/* Maximum size of input file, in bytes (keep under 100MB): */

// NOTE: this function cannot have the argument
// because this is used in Mutator.

template <class Tag>
constexpr u32 GetMaxFile(void) {
  return 1 * 1024 * 1024;
}

/* The same, for the test case minimizer: */
template <class State>
constexpr u32 GetTminMaxFile(State&) {
  return 10 * 1024 * 1024;
}

/* Block normalization steps for afl-tmin: */
template <class State>
constexpr u32 GetTminSetMinSize(State&) {
  return 4;
}

template <class State>
constexpr u32 GetTminSetSteps(State&) {
  return 128;
}

/* Maximum dictionary token size (-x), in bytes: */
template <class Testcase>
constexpr u32 GetMaxDictFile(AFLStateTemplate<Testcase>& state) {
  return state.extras.empty() ? 0u : u32(state.extras.back().data.size());
}

/* Length limits for auto-detected dictionary tokens: */
template <class State>
constexpr u32 GetMinAutoExtra(State&) {
  return 3;
}

template <class State>
constexpr u32 GetMaxAutoExtra(State&) {
  return 32;
}

/* Maximum number of user-specified dictionary tokens to use in deterministic
    steps; past this point, the "extras/user" step will be still carried out,
    but with proportionally lower odds: */
template <class State>
constexpr u32 GetMaxDetExtras(State&) {
  return 200;
}

/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
    (first value), and to keep in memory as candidates. The latter should be
   much higher than the former. */
template <class State>
constexpr u32 GetUseAutoExtras(State&) {
  return 50;
}

template <class State>
constexpr u32 GetMaxAutoExtras(State& state) {
  return GetUseAutoExtras(state) * 10;
}

/* Scaling factor for the effector map used to skip some of the more
    expensive deterministic steps. The actual divisor is set to
    2^EFF_MAP_SCALE2 bytes: */

// NOTE: this function cannot have the argument
// because this is used in afl::util.

template <class State>
constexpr u32 GetEffMapScale2(void) {
  return 3;
}

/* Minimum input file length at which the effector logic kicks in: */
template <class State>
constexpr u32 GetEffMinLen(State&) {
  return 128;
}

/* Maximum effector density past which everything is just fuzzed
    unconditionally (%): */
template <class State>
constexpr u32 GetEffMaxPerc(State&) {
  return 90;
}

/* UI refresh frequency (Hz): */
template <class State>
constexpr u32 GetUiTargetHz(State&) {
  return 5;
}

/* Fuzzer stats file and plot update intervals (sec): */
template <class State>
constexpr u32 GetStatsUpdateSec(State&) {
  return 60;
}

template <class State>
constexpr u32 GetPlotUpdateSec(State&) {
  return 60;
}

/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */
template <class State>
constexpr u32 GetAvgSmoothing(State&) {
  return 16;
}

/* Limits for the test case trimmer. The absolute minimum chunk size; and
    the starting and ending divisors for chopping up the input file: */
template <class State>
constexpr u32 GetTrimMinBytes(State&) {
  return 4;
}

template <class State>
constexpr u32 GetTrimStartSteps(State&) {
  return 16;
}

template <class State>
constexpr u32 GetTrimEndSteps(State&) {
  return 1024;
}

template <class State>
constexpr std::uint32_t GetSyncInterval(State&) {
  return 30u * 60u;
}

/* A made-up hashing seed: */

// NOTE: this function cannot have the argument
// because this is used in Feedbacks.

template <class Tag>
constexpr u32 GetHashConst(void) {
  return 0xa5b35705;
}

}  // namespace fuzzuf::algorithm::afl::option
