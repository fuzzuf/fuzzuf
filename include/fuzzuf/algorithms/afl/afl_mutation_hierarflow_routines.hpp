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

#include <memory>
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

template<class State>
using AFLMutInputType = bool(AFLMutatorTemplate<State>&);

template<class State>
using AFLMutCalleeRef = NullableRef<HierarFlowCallee<AFLMutInputType<State>>>;

using AFLMutOutputType = bool(const u8*, u32);

template<class State>
struct BitFlip1WithAutoDictBuildTemplate
    : public HierarFlowRoutine<
        AFLMutInputType<State>,
        AFLMutOutputType
    > {
public:
    BitFlip1WithAutoDictBuildTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using BitFlip1WithAutoDictBuild = BitFlip1WithAutoDictBuildTemplate<AFLState>;

template<class State>
struct BitFlipOtherTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    BitFlipOtherTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using BitFlipOther = BitFlipOtherTemplate<AFLState>;

template<class State>
struct ByteFlip1WithEffMapBuildTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    ByteFlip1WithEffMapBuildTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using ByteFlip1WithEffMapBuild = ByteFlip1WithEffMapBuildTemplate<AFLState>;

template<class State>
struct ByteFlipOtherTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    ByteFlipOtherTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using ByteFlipOther = ByteFlipOtherTemplate<AFLState>;

template<class State>
struct ArithTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    ArithTemplate(State &state);

    // Because, in ArithTemplate, we need to access the buffer as u8*, u16*, u32*,
    // we create a template function which describes each step of the stage
    template<class UInt>
    bool DoArith(AFLMutatorTemplate<State> &mutator);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using Arith = ArithTemplate<AFLState>;

template<class State>
template<class UInt>
bool ArithTemplate<State>::DoArith(AFLMutatorTemplate<State> &mutator) {
    using Tag = typename State::Tag;

    using afl::util::EFF_APOS;
    constexpr auto byte_width = sizeof(UInt);   

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;
    u32 num_mutable_pos = mutator.GetLen() + 1 - byte_width;

    state.stage_short = "arith" + std::to_string(byte_width * 8);
    state.stage_name = "arith " + std::to_string(byte_width * 8) + "/8";
    state.stage_cur = 0;

    // the number of mutations conducted for each byte
    int times_mut_per_unit = 2; // AddN, SubN
    if (byte_width >= 2) times_mut_per_unit *= 2; // Big Endian, Little Endian

    state.stage_max = times_mut_per_unit * num_mutable_pos * option::GetArithMax<Tag>();
    
    for (u32 i=0; i < num_mutable_pos; i++) {
        const auto head = EFF_APOS<Tag>(i);
        const auto tail = EFF_APOS<Tag>(i + byte_width - 1);
        bool should_mutate = std::memchr(&state.eff_map[head], 1, tail-head+1) != NULL;

        if (!should_mutate) {
            state.stage_max -= times_mut_per_unit * option::GetArithMax<Tag>();
            continue;
        }

        state.stage_cur_byte = i;
        for (s32 j=1; j <= (s32)option::GetArithMax<Tag>(); j++) { 
            // deal with Little Endian
            state.stage_val_type = option::STAGE_VAL_LE;

            if (mutator.template AddN<UInt>(i, j, false)) {
                state.stage_cur_val = j;
                if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;
                state.stage_cur++;
                mutator.template RestoreOverwrite<UInt>();
            } else state.stage_max--;

            if (mutator.template SubN<UInt>(i, j, false)) {
                state.stage_cur_val = -j;
                if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;
                state.stage_cur++;
                mutator.template RestoreOverwrite<UInt>();
            } else state.stage_max--;
            
            if (byte_width == 1) continue;

            // Big Endian
            state.stage_val_type = option::STAGE_VAL_BE;

            if (mutator.template AddN<UInt>(i, j, true)) {
                state.stage_cur_val = j;
                if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;
                state.stage_cur++;
                mutator.template RestoreOverwrite<UInt>();
            } else state.stage_max--;

            if (mutator.template SubN<UInt>(i, j, true)) {
                state.stage_cur_val = -j;
                if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;
                state.stage_cur++;
                mutator.template RestoreOverwrite<UInt>();
            } else state.stage_max--;

        }
    }

    int stage_idx;
    if (byte_width == 1) stage_idx = option::STAGE_ARITH8;
    else if (byte_width == 2) stage_idx = option::STAGE_ARITH16;
    else if (byte_width == 4) stage_idx = option::STAGE_ARITH32;

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
    state.stage_finds[stage_idx] += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[stage_idx] += state.stage_max;

    return false;
}

template<class State>
struct InterestTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    InterestTemplate(State &state);

    // Because, in InterestTemplate, we need to access the buffer as u8*, u16*, u32*,
    // we create a template function which describes each step of the stage
    template<class UInt>
    bool DoInterest(AFLMutatorTemplate<State> &mutator);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using Interest = InterestTemplate<AFLState>;

template<class State>
template<class UInt>
bool InterestTemplate<State>::DoInterest(AFLMutatorTemplate<State> &mutator) {
    using Tag = typename State::Tag;

    using afl::util::EFF_APOS;
    constexpr auto byte_width = sizeof(UInt);

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;
    u32 num_mutable_pos = mutator.GetLen() + 1 - byte_width;

    using SInt = typename std::make_signed<UInt>::type;

    // We can't assign values to reference types like below
    // So we have to use a pointer...
    const std::vector<SInt>* interest_values;
    if      constexpr (byte_width == 1) interest_values = &Mutator<Tag>::interesting_8;
    else if constexpr (byte_width == 2) interest_values = &Mutator<Tag>::interesting_16;
    else if constexpr (byte_width == 4) interest_values = &Mutator<Tag>::interesting_32;

    int num_endians;
    if constexpr (byte_width == 1) num_endians = 1;
    else num_endians = 2;

    state.stage_short = "int" + std::to_string(byte_width * 8);
    state.stage_name = "interest " + std::to_string(byte_width * 8) + "/8";
    state.stage_cur = 0;
    state.stage_max = num_endians * num_mutable_pos * interest_values->size();

    for (u32 i=0; i < num_mutable_pos; i++) {
        /* Let's consult the effector map... */

        const auto head = EFF_APOS<Tag>(i);
        const auto tail = EFF_APOS<Tag>(i + byte_width - 1);
        bool should_mutate = std::memchr(&state.eff_map[head], 1, tail-head+1) != NULL;

        if (!should_mutate) {
            state.stage_max -= num_endians * interest_values->size();
            continue;
        }

        state.stage_cur_byte = i;

        for (u32 j=0; j < interest_values->size(); j++) {
            state.stage_cur_val = (*interest_values)[j];

            if (mutator.template InterestN<UInt>(i, j, false)) {
                state.stage_val_type = option::STAGE_VAL_LE;

                if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;

                state.stage_cur++;
                mutator.template RestoreOverwrite<UInt>();
            } else state.stage_max--;

            if constexpr (byte_width == 1) continue;

            if (mutator.template InterestN<UInt>(i, j, true)) {
                state.stage_val_type = option::STAGE_VAL_BE;

                if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) return true;

                state.stage_cur++;
                mutator.template RestoreOverwrite<UInt>();
            } else state.stage_max--;
        }
    }

    int stage_idx;
    if constexpr (byte_width == 1) stage_idx = option::STAGE_INTEREST8;
    else if constexpr (byte_width == 2) stage_idx = option::STAGE_INTEREST16;
    else if constexpr (byte_width == 4) stage_idx = option::STAGE_INTEREST32;

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;
    state.stage_finds[stage_idx] += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[stage_idx] += state.stage_max;

    return false;
}

// the stage of overwriting with dictionary
// there are two options:
//   a) use user-defined dictionary b) use automatically created dictionary
// they are different stages but the processes are almost the same
// so we put them into one template function
template<class State, bool is_auto>
struct DictOverwriteTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    DictOverwriteTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

template<class State, bool is_auto>
DictOverwriteTemplate<State, is_auto>::DictOverwriteTemplate(State &state)
    : state(state) {}

template<class State, bool is_auto>
AFLMutCalleeRef<State> DictOverwriteTemplate<State, is_auto>::operator()(
    AFLMutatorTemplate<State>& mutator
) {
    // skip this step if the dictionary is empty
    if constexpr(is_auto) {
        if (state.a_extras.empty()) return this->GoToDefaultNext();
    } else {
        if (state.extras.empty())   return this->GoToDefaultNext();
    }

    /* Overwrite with user-supplied extras. */

    using Tag = typename State::Tag;

    using afl::util::EFF_APOS;
    using afl::util::EFF_SPAN_ALEN;

    u32 num_used_extra;
    if constexpr (is_auto) {
        state.stage_name = "auto extras (over)";
        state.stage_short = "ext_AO";
        num_used_extra = std::min<u32>(state.a_extras.size(), option::GetUseAutoExtras(state));
    } else {
        state.stage_name = "user extras (over)";
        state.stage_short = "ext_UO";
        num_used_extra = state.extras.size();
    }
    state.stage_cur = 0;
    state.stage_max = mutator.GetLen() * num_used_extra;

    state.stage_val_type = option::STAGE_VAL_NONE;

    u64 orig_hit_cnt = state.queued_paths + state.unique_crashes;

    auto& extras = is_auto ? state.a_extras : state.extras;

    for (u32 i=0; i<mutator.GetLen(); i++) {
        state.stage_cur_byte = i;

        /* Extras are sorted by size, from smallest to largest. This means
           that we don't have to worry about restoring the buffer in
           between writes at a particular offset determined by the outer
           loop. */

        u32 last_len = 0;
        for (auto itr=extras.begin(); itr != extras.begin() + num_used_extra; itr++) {
            auto& extra = *itr;

            /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
               skip them if there's no room to insert the payload, if the token
               is redundant, or if its entire span has no bytes set in the
               effector map. */

            using afl::util::UR;
            if (!is_auto) {
                if ( extras.size() > option::GetMaxDetExtras(state)
                  && UR(state.extras.size(), state.rand_fd) >= option::GetMaxDetExtras(state)) {
                    state.stage_max--;
                    continue;
                }
            }

            u32 extra_sz = extra.data.size();
            if ( extra_sz > mutator.GetLen() - i
              || !std::memcmp(&extra.data[0], mutator.GetBuf() + i, extra_sz)
              || !std::memchr(&state.eff_map[EFF_APOS<Tag>(i)], 1, EFF_SPAN_ALEN<Tag>(i, extra_sz))
            ) {
                state.stage_max--;
                continue;
            }

            last_len = extra_sz;
            mutator.Replace(i, &extra.data[0], last_len);

            if (this->CallSuccessors(mutator.GetBuf(), mutator.GetLen())) {
                this->SetResponseValue(true);
                return this->GoToParent();
            }

            state.stage_cur++;
        }

        mutator.Replace(i, mutator.GetSource().GetBuf() + i, last_len);
    }

    u64 new_hit_cnt = state.queued_paths + state.unique_crashes;

    int stage_idx;
    if (is_auto) {
        stage_idx = option::STAGE_EXTRAS_AO;
    } else {
        stage_idx = option::STAGE_EXTRAS_UO;
    }

    state.stage_finds[stage_idx]  += new_hit_cnt - orig_hit_cnt;
    state.stage_cycles[stage_idx] += state.stage_max;

    return this->GoToDefaultNext();
}

template<class State>
using UserDictOverwriteTemplate = DictOverwriteTemplate<State, false>;

template<class State>
using AutoDictOverwriteTemplate = DictOverwriteTemplate<State, true>;

using UserDictOverwrite = UserDictOverwriteTemplate<AFLState>;
using AutoDictOverwrite = AutoDictOverwriteTemplate<AFLState>;

template<class State>
struct UserDictInsertTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {
public:
    UserDictInsertTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);

private:
    State &state;
};

using UserDictInsert = UserDictInsertTemplate<AFLState>;

template<class State>
struct HavocBaseTemplate
    : public HierarFlowRoutine<
          AFLMutInputType<State>,
          AFLMutOutputType
      > {

public:
    HavocBaseTemplate(State &state);
    virtual ~HavocBaseTemplate() {}

    template<typename CaseDistrib, typename CustomCases>
    bool DoHavoc(
        AFLMutatorTemplate<State>& mutator,
        CaseDistrib case_distrib,
        CustomCases custom_cases,
        const std::string &stage_name,
        const std::string &stage_short,
        u32 perf_score,
        s32 stage_max_multiplier, 
        int stage_idx
    );

    virtual AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator) = 0;

protected:
    State &state;
};

using HavocBase = HavocBaseTemplate<AFLState>;

template<class State>
struct HavocTemplate : public HavocBaseTemplate<State> {
public:
    HavocTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);
};

using Havoc = HavocTemplate<AFLState>;

template<class State>
struct SplicingTemplate : public HavocBaseTemplate<State> {
public:
    SplicingTemplate(State &state);

    AFLMutCalleeRef<State> operator()(AFLMutatorTemplate<State>& mutator);
};

using Splicing = SplicingTemplate<AFLState>;

} // namespace fuzzuf::algorithm::afl::routine::mutation

#include "fuzzuf/algorithms/afl/templates/afl_mutation_hierarflow_routines.hpp"
