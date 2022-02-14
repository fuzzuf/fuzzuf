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

#include "fuzzuf/algorithms/ijon/ijon_havoc.hpp"

#include <random>
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"

namespace fuzzuf::algorithm::ijon::havoc {

/**
 *  @enum IJONExtraHavocCase
 *  IJON introduces some custom cases in Mutator::Havoc 
 *  because it slightly modified some of the cases in AFL's havoc.
 *  This (C-style) enum assigns non-egative integers to each of these cases
 *  so that the integers directly follow the last integer in enum HavocCase.
 */
enum IJONExtraHavocCase : u32 {
  IJON_DELETE_BYTES = NUM_CASE, // directly follow HavocCase
  IJON_INSERT_EXTRA,
  IJON_INSERT_AEXTRA,
  IJON_NUM_CASE // this represents the number of cases in IJON's havoc
};

static constexpr std::array<double, IJON_NUM_CASE> IJONGetCaseWeights(bool has_extras, bool has_aextras) {
    using afl::util::AFLGetCaseWeights;

    // IJON's probability distribution of mutation operators is based on that of AFL.
    std::array<double, NUM_CASE> base_weights = AFLGetCaseWeights(has_extras, has_aextras);

    // The number of cases in havoc in IJON is different than in AFL.
    // So we need to copy it first.
    std::array<double, IJON_NUM_CASE> ret{};
    for (u32 i=0; i<NUM_CASE; i++) {
        ret[i] = base_weights[i];
    }

    // IJON replaces some of the cases in havoc with its custom cases.
    // So we need to change the weights of these cases in the probability distributions accordingly.
    ret[IJON_DELETE_BYTES] = ret[DELETE_BYTES];
    ret[DELETE_BYTES]  = 0.0;

    ret[IJON_INSERT_EXTRA] = ret[INSERT_EXTRA];
    ret[INSERT_EXTRA]  = 0.0;

    ret[IJON_INSERT_AEXTRA] = ret[INSERT_AEXTRA];
    ret[INSERT_AEXTRA] = 0.0;

    return ret;
}

/**
 * @fn IJONHavocCaseDistrib
 * This function represents the probability distributions of mutation operators in the havoc mutation of IJON.
 * Depending on whether IJON has a dictionary for a PUT, the function employs different distributions.
 */
u32 IJONHavocCaseDistrib(
    const std::vector<afl::dictionary::AFLDictData>& extras, 
    const std::vector<afl::dictionary::AFLDictData>& a_extras
) {
    
    // FIXME: replace this engine with our pRNG later to avoid being flooded with pRNGs.
    static std::random_device seed_gen;
    static std::mt19937 engine(seed_gen());

    // Static part: the following part doesn't run after a fuzzing campaign starts.

    constexpr std::array<double, IJON_NUM_CASE> weight_set[2][2] = {
        { IJONGetCaseWeights(false, false), IJONGetCaseWeights(false, true) },
        { IJONGetCaseWeights(true,  false), IJONGetCaseWeights(true,  true) }
    };

    // FIXME: actually, libstdc++'s discrete_distribution doesn't use Walker's alias method...
    // We should implement it by ourselves...
    static std::discrete_distribution<u32> dists[2][2] = {
        { std::discrete_distribution<u32>(weight_set[0][0].begin(), weight_set[0][0].end()),
          std::discrete_distribution<u32>(weight_set[0][1].begin(), weight_set[0][1].end()) },
        { std::discrete_distribution<u32>(weight_set[1][0].begin(), weight_set[1][0].end()),
          std::discrete_distribution<u32>(weight_set[1][1].begin(), weight_set[1][1].end()) },
    };

    // Dynamic part: the following part runs during a fuzzing campaign

    bool has_extras  = !extras.empty();
    bool has_aextras = !a_extras.empty();
    return dists[has_extras][has_aextras](engine);
}

void IJONCustomCases(
    u32 case_idx,
    u8*& outbuf,
    u32& len,
    const std::vector<afl::dictionary::AFLDictData>& extras,
    const std::vector<afl::dictionary::AFLDictData>& a_extras
) {
    switch (case_idx) {
    case IJON_DELETE_BYTES:
        // IJON intentionally ignores DELETE_BYTES and does nothing here.
        // Nevertheless, we don't remove this case because removing this case 
        // slightly increases the expected number of mutation operators applied at once in havoc.
        break;

    case IJON_INSERT_EXTRA : [[fallthrough]];
    case IJON_INSERT_AEXTRA: {
        // IJON always inserts keywords at the end of inputs.
        u32 insert_at = len;

        /* Insert an extra. Do the same dice-rolling stuff as for the
           previous case. */

        bool use_auto = case_idx == IJON_INSERT_AEXTRA;

        // CaseDistrib must not select these cases when there is no dictionary.
        // But this is difficult to be guaranteed, so we put asserts here.
        if (use_auto) DEBUG_ASSERT(!a_extras.empty());
        else          DEBUG_ASSERT(!extras.empty());

        // FIXME: replace AFL's pRNGs with ours later.
        using afl::util::UR;
        using afl::dictionary::AFLDictData;
        u32 idx = use_auto ? UR(a_extras.size(), -1) : UR(extras.size(), -1);
        const AFLDictData &extra = use_auto ? a_extras[idx] : extras[idx];

        u32 extra_len = extra.data.size();
        if (len + extra_len >= afl::option::GetMaxFile<option::IJONTag>()) break;

        u8* new_buf = new u8[len + extra_len];

        /* Head */
        std::memcpy(new_buf, outbuf, insert_at);

        /* Inserted part */
        std::memcpy(new_buf + insert_at, &extra.data[0], extra_len);

        /* Tail */
        std::memcpy(new_buf + insert_at + extra_len, outbuf + insert_at,
                len - insert_at);

        delete[] outbuf;
        outbuf = new_buf;
        len += extra_len;
        
        break;
    }

    default:
        break;
    }
}

} // namespace fuzzuf::algorithm::ijon::havoc
