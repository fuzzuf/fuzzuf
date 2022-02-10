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
#include "fuzzuf/algorithms/afl/afl_util.hpp"

#include <random>
#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

// A temporary criteria for deciding whether to put new utils here or make them class member functions:
//     - AFL-specific utility functions that may be useful to implement AFL-derived algorithms should be added here
//     - However, place them where appropriate other than here if such algorithms may change their implementations
//       to change the behavior (e.g. implement them as AFLState's member functions and make them inheritable).
//     - Basically, utilities having large side-effects (e.g. modifying the state) should not be placed here
//        * Rather, it should be AFLState's member function
//        * Yet, it does not apply to functions need to be called from multiple classes (e.g. RetryCalibrate and SaveIfInteresting)
//          * The advantage of implementing a utility here is that side-effects can be observed clearly since it is not
//            referenced through member variables but always through arguments

namespace fuzzuf::algorithm::afl::util {

u32 UR(u32 limit, int rand_fd) {
    static u32 rand_cnt;
    if (rand_fd != -1 && unlikely(!rand_cnt--)) {
        u32 seed[2];
        Util::ReadFile(rand_fd, &seed, sizeof(seed));
        srandom(seed[0]);

        using option::AFLTag;
        using option::GetReseedRng;
        rand_cnt = (GetReseedRng<AFLTag>() / 2) + (seed[1] % GetReseedRng<AFLTag>());
    }
    return random() % limit;
}

/* Describe all the integers with five characters or less */

std::string DescribeInteger(u64 val) {
#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
        if (val < (_divisor) * (_limit_mult)) { \
            return Util::StrPrintf(_fmt, ((_cast)val) / (_divisor)); \
        } \
    } while (0)

    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu", u64);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1000, 99.95, "%0.01fk", double);

    /* 100k - 999k */
    CHK_FORMAT(1000, 1000, "%lluk", u64);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

    /* 100M - 999M */
    CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

    /* 100G - 999G */
    CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

    /* 100T+ */
    return "infty";
}

/* Describe float. Similar to the above, except with a single 
   static buffer. */

std::string DescribeFloat(double val) {
    if (val < 99.995) {
        return Util::StrPrintf("%0.02f", val);
    }

    if (val < 999.95) {
        return Util::StrPrintf("%0.01f", val);
    }

    return DescribeInteger((u64)val);
}

std::string DescribeMemorySize(u64 val) {
    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu B", u64);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

    /* 100k - 999k */
    CHK_FORMAT(1024, 1000, "%llu kB", u64);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

    /* 100M - 999M */
    CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

    /* 100G - 999G */
    CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

    /* 100T+ */
    return "infty";
}

/* Describe time delta. Returns one static buffer, 34 chars of less. */

std::string DescribeTimeDelta(u64 cur_ms, u64 event_ms) {

  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  return Util::StrPrintf("%s days, %u hrs, %u min, %u sec", 
                            DescribeInteger(t_d).c_str(), t_h, t_m, t_s);
}

// In the following section, we define the probability distribution for the havoc mutation.
// The definition consists of the following two steps:
//   1. initialize the weights that represent 
//      the probabilities of each case being selected in Havoc.
//   2. initialize discrete_distribution with the weights.
//
// The problem here is that the weights should be changed depending on whether AFL has
// extras and auto extras(constant strings included in the dictionaries).
// Therefore, we need to define 4 sets of weights, each of which represents the probabilities
// in the case where AFL has {some, no} extras and {some, no} auto extras.
//
// Also, right below, we use constexpr and static variables a lot.
// AFL doesn't modify the weights and distributions dynamically,
// so we don't want to initialize them more than once. 
// This is why the following functions use constexpr and are a little bit hard to read.

// FIXME: is there any better way than this?


// Return the weights that represent the probabilities of each case being selected in Havoc.
// Ridiculously, we need a constexpr function just in order to 
// initialize static arrays with enum constants(i.e. to use a kind of designated initialization)

static constexpr std::array<double, NUM_CASE> GetCaseWeights(
    // we provide 4 types of probability weights, depending on 
    //  1. whether AFL has any extras and,
    //  2. whether AFL has auto extras
    bool has_extras, 
    bool has_a_extras 
) {
    std::array<double, NUM_CASE> weights {};

    // We use constexpr + assignment, instead of designated initialization of C lang
    // This allows us to easily assign and check the weight of each case in havoc.

    weights[FLIP1] = 2.0;
    weights[XOR]   = 2.0;

    weights[DELETE_BYTES] = 4.0; // case 11 ... 12

    weights[CLONE_BYTES]     = 1.5; // UR(4) != 0 in case 13
    weights[INSERT_SAME_BYTE] = 0.5; // UR(4) == 0 in case 13

    // The following two cases are the same as the above two cases
    weights[OVERWRITE_WITH_CHUNK]    = 1.5;
    weights[OVERWRITE_WITH_SAME_BYTE] = 0.5;

    weights[INT8]     = 2.0;
    weights[INT16_LE] = 1.0; // UR(2) == 1 in case 2
    weights[INT16_BE] = 1.0; // UR(2) == 0 in case 2
    weights[INT32_LE] = 1.0; // UR(2) == 1 in case 3
    weights[INT32_BE] = 1.0; // UR(2) == 0 in case 3

    // SUB and ADD are the same as INT
    weights[SUB8]     = 2.0;
    weights[SUB16_LE] = 1.0;
    weights[SUB16_BE] = 1.0;
    weights[SUB32_LE] = 1.0;
    weights[SUB32_BE] = 1.0;

    weights[ADD8]     = 2.0;
    weights[ADD16_LE] = 1.0;
    weights[ADD16_BE] = 1.0;
    weights[ADD32_LE] = 1.0;
    weights[ADD32_BE] = 1.0;
 
    if (has_extras && has_a_extras) {
        weights[INSERT_EXTRA]          = 1.0;
        weights[OVERWRITE_WITH_EXTRA]  = 1.0;
        weights[INSERT_AEXTRA]         = 1.0;
        weights[OVERWRITE_WITH_AEXTRA] = 1.0;
    } else if (has_extras) {
        weights[INSERT_EXTRA]          = 2.0;
        weights[OVERWRITE_WITH_EXTRA]  = 2.0;
    } else if (has_a_extras) {
        weights[INSERT_AEXTRA]         = 2.0;
        weights[OVERWRITE_WITH_AEXTRA] = 2.0;
    }

    return weights;
}

u32 HavocCaseDistrib(
    const std::vector<dictionary::AFLDictData>& extras, 
    const std::vector<dictionary::AFLDictData>& a_extras
) {
    // Static part: the following part doesn't run after a fuzzing campaign starts.

    constexpr std::array<double, NUM_CASE> weight_set[2][2] = {
        { GetCaseWeights(false, false), GetCaseWeights(false, true) },
        { GetCaseWeights(true,  false), GetCaseWeights(true,  true) }
    };

    using fuzzuf::utils::random::WalkerDiscreteDistribution;
    WalkerDiscreteDistribution<u32> dists[2][2] = {
      { WalkerDiscreteDistribution<u32>(weight_set[0][0].cbegin(),
                                        weight_set[0][0].cend()),
        WalkerDiscreteDistribution<u32>(weight_set[0][1].cbegin(),
                                        weight_set[0][1].cend()) },
      { WalkerDiscreteDistribution<u32>(weight_set[1][0].cbegin(),
                                        weight_set[1][0].cend()),
        WalkerDiscreteDistribution<u32>(weight_set[1][1].cbegin(),
                                        weight_set[1][1].cend()) }
    };

    // Dynamic part: the following part runs during a fuzzing campaign

    bool has_extras  = !extras.empty();
    bool has_aextras = !a_extras.empty();
    return dists[has_extras][has_aextras]();
}

} // namespace fuzzuf::algorithm::afl::util
