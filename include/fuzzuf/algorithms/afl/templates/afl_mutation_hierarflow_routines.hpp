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
#include "fuzzuf/exec_input/exec_input.hpp"

#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

template<class State>
BitFlip1WithAutoDictBuildTemplate<State>::BitFlip1WithAutoDictBuildTemplate(
    State &state
)
    : state(state) {}

template<class State>
AFLMutCalleeRef<State> BitFlip1WithAutoDictBuildTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {

    /*********************************************
     * SIMPLE BITFLIP (+dictionary construction) *
     *********************************************/

    state.prev_cksum = state.queue_cur_exec_cksum;

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;

    state.stage_short = "flip1";
    state.stage_name = "bitflip 1/1";
    state.stage_max = mutator.GetLen() << 3;

    state.a_len = 0;
    state.a_collect.clear();
    state.SetShouldConstructAutoDict(false);

    for (state.stage_cur=0; state.stage_cur < state.stage_max; state.stage_cur++) {
        state.stage_cur_byte = state.stage_cur >> 3;

        // If the following conditions are met, consider appending Auto Extra values in the successor
        // For the details, check fuzzuf::algorithm::afl::routine::update::ConstructAutoDict

        if (!state.setting->dumb_mode) {
            state.SetShouldConstructAutoDict((state.stage_cur & 7) == 7);
        }

        mutator.FlipBit(state.stage_cur, 1);
        if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) {
            this->SetResponseValue(true);
            return this->GoToParent();
        }
        mutator.FlipBit(state.stage_cur, 1);
    }

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
    state.stage_finds[option::STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[option::STAGE_FLIP1] += state.stage_max;

    return this->GoToDefaultNext();
}

template<class State>
BitFlipOtherTemplate<State>::BitFlipOtherTemplate(State &state) : state(state) {}

template<class State>
AFLMutCalleeRef<State> BitFlipOtherTemplate<State>::operator()(AFLMutatorTemplate<State>& mutator) {
    /*********************************************
     * SIMPLE BITFLIP                            *
     *********************************************/

    int stage_idxs[] = {
        option::STAGE_FLIP2,
        option::STAGE_FLIP4
    };

    for (u32 bit_width=2, idx=0; bit_width <= 4; bit_width *= 2, idx++) {
        u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;

        state.stage_short = "flip" + std::to_string(bit_width);
        state.stage_name = "bitflip " + std::to_string(bit_width) + "/1";
        state.stage_max = (mutator.GetLen() << 3) + 1 - bit_width;

        for (state.stage_cur=0; state.stage_cur < state.stage_max; state.stage_cur++) {
            state.stage_cur_byte = state.stage_cur >> 3;

            mutator.FlipBit(state.stage_cur, bit_width);
            if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) {
                this->SetResponseValue(true);
                return this->GoToParent();
            }
            mutator.FlipBit(state.stage_cur, bit_width);
        }

        u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
        state.stage_finds[stage_idxs[idx]] += new_hit_cnt - orig_hit_cnt;
        state.stage_cycles[stage_idxs[idx]] += state.stage_max;
    }

    return this->GoToDefaultNext();
}

template<class State>
ByteFlip1WithEffMapBuildTemplate<State>::ByteFlip1WithEffMapBuildTemplate(
    State &state
)
    : state(state) {}

template<class State>
AFLMutCalleeRef<State> ByteFlip1WithEffMapBuildTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    /* Walking byte. */

    using Tag = typename State::Tag;

    using afl::util::EFF_APOS;
    using afl::util::EFF_ALEN;

    state.eff_map.assign(EFF_ALEN<Tag>(mutator.GetLen()), 0);
    state.eff_map[0] = 1;
    state.eff_cnt = 1;
    if (EFF_APOS<Tag>(mutator.GetLen() - 1) != 0) {
        state.eff_map[EFF_APOS<Tag>(mutator.GetLen() - 1)] = 1;
        state.eff_cnt++;
    }

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;
    u32 num_mutable_pos = mutator.GetLen();

    state.stage_short = "flip8";
    state.stage_name = "bitflip 8/8";
    state.stage_cur = 0;
    state.stage_max = num_mutable_pos;

    for (u32 i=0; i < num_mutable_pos; i++) {
        state.stage_cur_byte = i;

        mutator.FlipByte(state.stage_cur, 1);
        if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) {
            this->SetResponseValue(true);
            return this->GoToParent();
        }
        mutator.FlipByte(state.stage_cur, 1);

        state.stage_cur++;
    }

    if (state.eff_cnt != EFF_ALEN<Tag>(mutator.GetLen()) &&
        state.eff_cnt * 100 / EFF_ALEN<Tag>(mutator.GetLen()) > option::GetEffMaxPerc(state)) {

        std::memset(&state.eff_map[0], 1, EFF_ALEN<Tag>(mutator.GetLen()));
        state.blocks_eff_select += EFF_ALEN<Tag>(mutator.GetLen());
    } else {
        state.blocks_eff_select += state.eff_cnt;
    }

    state.blocks_eff_total += EFF_ALEN<Tag>(mutator.GetLen());

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
    state.stage_finds[option::STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[option::STAGE_FLIP8] += state.stage_max;

    return this->GoToDefaultNext();
}

template<class State>
ByteFlipOtherTemplate<State>::ByteFlipOtherTemplate(State &state)
    : state(state) {}

template<class State>
AFLMutCalleeRef<State> ByteFlipOtherTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    /* Walking byte. */

    using Tag = typename State::Tag;

    using afl::util::EFF_APOS;

    int stage_idxs[] = {
        option::STAGE_FLIP16,
        option::STAGE_FLIP32
    };

    for (u32 byte_width=2, idx=0; byte_width <= 4; byte_width *= 2, idx++) {
        // if the input is too short, then it's impossible
        if (mutator.GetLen() < byte_width) return this->GoToDefaultNext();

        u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;
        u32 num_mutable_pos = mutator.GetLen() + 1 - byte_width;

        state.stage_short = "flip" + std::to_string(byte_width * 8);
        state.stage_name = "bitflip " + std::to_string(byte_width * 8) + "/8";
        state.stage_cur = 0;
        state.stage_max = num_mutable_pos;

        for (u32 i=0; i < num_mutable_pos; i++) {
            const auto head = EFF_APOS<Tag>(i);
            const auto tail = EFF_APOS<Tag>(i + byte_width - 1);
            bool should_mutate = std::memchr(&state.eff_map[head], 1, tail-head+1) != NULL;

            if (!should_mutate) {
                state.stage_max--;
                continue;
            }

            state.stage_cur_byte = i;

            mutator.FlipByte(i, byte_width);
            if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) {
                this->SetResponseValue(true);
                return this->GoToParent();
            }
            mutator.FlipByte(i, byte_width);

            state.stage_cur++;
        }

        u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
        state.stage_finds[stage_idxs[idx]]  += new_hit_cnt - orig_hit_cnt;
        state.stage_cycles[stage_idxs[idx]] += state.stage_max;
    }

    return this->GoToDefaultNext();
}

template<class State>
ArithTemplate<State>::ArithTemplate(State &state) : state(state) {}

template<class State>
AFLMutCalleeRef<State> ArithTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    /**********************
     * ARITHMETIC INC/DEC *
     **********************/

    if (state.no_arith) return this->GoToDefaultNext();

    if (DoArith<u8>(mutator)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }
    if (mutator.GetLen() < 2) return this->GoToDefaultNext();

    if (DoArith<u16>(mutator)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }
    if (mutator.GetLen() < 4) return this->GoToDefaultNext();

    if (DoArith<u32>(mutator)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }
    return this->GoToDefaultNext();
}

template<class State>
InterestTemplate<State>::InterestTemplate(State &state) : state(state) {}

template<class State>
AFLMutCalleeRef<State> InterestTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    /**********************
     * INTERESTING VALUES *
     **********************/

    if (DoInterest<u8>(mutator)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }
    if (state.no_arith || mutator.GetLen() < 2) return this->GoToDefaultNext();

    if (DoInterest<u16>(mutator)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }
    if (mutator.GetLen() < 4) return this->GoToDefaultNext();

    if (DoInterest<u32>(mutator)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }
    return this->GoToDefaultNext();
}

template<class State>
UserDictInsertTemplate<State>::UserDictInsertTemplate(State &state)
    : state(state) {}

template<class State>
AFLMutCalleeRef<State> UserDictInsertTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    // skip this step if the dictionary is empty
    if (state.extras.empty()) return this->GoToDefaultNext();

    /* Insertion of user-supplied extras. */

    using Tag = typename State::Tag;

    state.stage_name = "user extras (insert)";
    state.stage_short = "ext_UI";
    state.stage_cur = 0;
    state.stage_max = state.extras.size() * (mutator.GetLen() + 1);

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;

    std::unique_ptr<u8[]> ex_tmp(new u8[mutator.GetLen() + option::GetMaxDictFile(state)]);
    for (u32 i=0; i <= mutator.GetLen(); i++) {
        state.stage_cur_byte = i;

       /* Extras are sorted by size, from smallest to largest. This means
          that once len + extras[j].len > MAX_FILE holds, the same is true for
          all the subsequent extras. */

        for (u32 j=0; j < state.extras.size(); j++) {
            auto &extra = state.extras[j];
            if (mutator.GetLen() + extra.data.size() > option::GetMaxFile<Tag>()) {
                s32 rem = state.extras.size() - j;
                state.stage_max -= rem;
                break;
            }

            /* Insert token */
            std::memcpy(ex_tmp.get() + i, &state.extras[j].data[0], state.extras[j].data.size());

            /* Copy tail */
            std::memcpy(ex_tmp.get() + i + state.extras[j].data.size(), mutator.GetBuf() + i, mutator.GetLen() - i);

            if (
                this->CallSuccessors(
                    ex_tmp.get(),
                    mutator.GetLen() + state.extras[j].data.size()
                )
            ) {
                this->SetResponseValue(true);
                return this->GoToParent();
            }

            state.stage_cur++;
        }

        /* Copy head */
        ex_tmp[i] = mutator.GetBuf()[i];
    }

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;

    state.stage_finds[option::STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[option::STAGE_EXTRAS_UI] += state.stage_max;

    return this->GoToDefaultNext();
}

template<class State>
HavocBaseTemplate<State>::HavocBaseTemplate(State &state)
    : state(state) {}

// Because the process details of Havoc will be used also in Splicing,
// we extract the "core" of Havoc into another HierarFlowRoutine, HavocBaseTemplate.
// both Havoc and Splicing will inherit this and use DoHavoc
template<class State>
template<typename CaseDistrib, typename CustomCases>
bool HavocBaseTemplate<State>::DoHavoc(
    AFLMutatorTemplate<State>& mutator,
    CaseDistrib case_distrib,
    CustomCases custom_cases,
    const std::string &stage_name,
    const std::string &stage_short,
    u32 perf_score,
    s32 stage_max_multiplier, // see directly below
    int stage_idx
) {
    state.stage_name = stage_name;
    state.stage_short = stage_short;
    state.stage_max = stage_max_multiplier * perf_score / state.havoc_div / 100;
    state.stage_cur_byte = -1;

    if (state.stage_max < option::GetHavocMin(state)) {
        state.stage_max = option::GetHavocMin(state);
    }

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;

    u64 havoc_queued = state.queued_paths;

    /* We essentially just do several thousand runs (depending on perf_score)
       where we take the input file and make random stacked tweaks. */

    for (state.stage_cur = 0; state.stage_cur < state.stage_max; state.stage_cur++) {
        using afl::util::UR;

        u32 use_stacking = 1 << (1 + UR(option::GetHavocStackPow2(state), state.rand_fd));

        state.stage_cur_val = use_stacking;
        mutator.Havoc(use_stacking, state.extras, state.a_extras, case_distrib, custom_cases);

        if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        mutator.RestoreHavoc();

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (state.queued_paths != havoc_queued) {
            if (perf_score <= option::GetHavocMaxMult(state) * 100) {
                state.stage_max *= 2;
                perf_score *= 2;
            }

            havoc_queued = state.queued_paths;
        }
    }

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
    state.stage_finds[stage_idx] += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[stage_idx] += state.stage_max;

    return false;
}

template<class State>
HavocTemplate<State>::HavocTemplate(State &state)
  : HavocBaseTemplate<State>(state) {}

template<class State>
AFLMutCalleeRef<State> HavocTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    // Declare the alias just to omit "this->" in this function.
    auto& state = this->state;

    s32 stage_max_multiplier;
    if (state.doing_det) stage_max_multiplier = option::GetHavocCyclesInit(state);
    else stage_max_multiplier = option::GetHavocCycles(state);

    using afl::util::AFLHavocCaseDistrib;
    using afl::dictionary::AFLDictData;

    if (this->DoHavoc(
                mutator,
                AFLHavocCaseDistrib,
                [](int, u8*&, u32&, const std::vector<AFLDictData>&, const std::vector<AFLDictData>&){},
                "havoc", "havoc",
                state.orig_perf, stage_max_multiplier,
                option::STAGE_HAVOC)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }

    return this->GoToDefaultNext();
}

template<class State>
SplicingTemplate<State>::SplicingTemplate(State &state)
    : HavocBaseTemplate<State>(state) {}

template<class State>
AFLMutCalleeRef<State> SplicingTemplate<State>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    // Declare the alias just to omit "this->" in this function.
    auto& state = this->state;

    if (!state.use_splicing || state.setting->ignore_finds) {
        return this->GoToDefaultNext();
    }

    u32 splice_cycle = 0;
    while (splice_cycle++ < option::GetSpliceCycles(state)
        && state.queued_paths > 1
        && mutator.GetSource().GetLen() > 1) {

        /* Pick a random queue entry and seek to it. Don't splice with yourself. */

        u32 tid;
        do {
            using afl::util::UR;
            tid = UR(state.queued_paths, state.rand_fd);
        } while (tid == state.current_entry);

        /* Make sure that the target has a reasonable length. */

        while (tid < state.case_queue.size()) {
            if (state.case_queue[tid]->input->GetLen() >= 2 &&
                tid != state.current_entry) break;

            ++tid;
        }

        if (tid == state.case_queue.size()) continue;

        auto &target_case = *state.case_queue[tid];
        state.splicing_with = tid;

        /* Read the testcase into a new buffer. */

        target_case.input->Load();
        bool success = mutator.Splice(*target_case.input);
        target_case.input->Unload();

        if (!success) {
            continue;
        }

        using afl::util::AFLHavocCaseDistrib;
        using afl::dictionary::AFLDictData;

        if (this->DoHavoc(mutator,
                    AFLHavocCaseDistrib,
                    [](int, u8*&, u32&, const std::vector<AFLDictData>&, const std::vector<AFLDictData>&){},
                    Util::StrPrintf("splice %u", splice_cycle),
                    "splice",
                    state.orig_perf, option::GetSpliceHavoc(state),
                    option::STAGE_SPLICE)) {
            this->SetResponseValue(true);
            return this->GoToParent();
        }

        mutator.RestoreSplice();
    }

    return this->GoToDefaultNext();
}

} // namespace fuzzuf::algorithm::afl::routine::mutation
