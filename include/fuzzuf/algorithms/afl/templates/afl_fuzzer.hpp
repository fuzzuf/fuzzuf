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

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"

namespace fuzzuf::algorithm::afl {

template<class State>
AFLFuzzerTemplate<State>::AFLFuzzerTemplate(
    std::unique_ptr<State>&& state_ref
) :
    state(std::move(state_ref))
{
    state->start_time = Util::GetCurTimeMs();

    BuildFuzzFlow();

    state->SaveCmdline(state->setting->argv);
    state->FixUpBanner(state->setting->argv[0]);
    state->CheckIfTty();

    state->ReadTestcases();
    state->PivotInputs();
    state->PerformDryRun();
}

template<class State>
AFLFuzzerTemplate<State>::~AFLFuzzerTemplate() {}

template<class State>
void AFLFuzzerTemplate<State>::BuildFuzzFlow() {
    using namespace fuzzuf::algorithm::afl::routine::other;
    using namespace fuzzuf::algorithm::afl::routine::mutation;
    using namespace fuzzuf::algorithm::afl::routine::update;

    using fuzzuf::hierarflow::CreateNode;
    using fuzzuf::hierarflow::CreateDummyParent;

    // Create the head node
    fuzz_loop = CreateDummyParent<void(void)>();

    // middle nodes(steps done before and after actual mutations)
    auto select_seed = CreateNode<SelectSeedTemplate<State>>(*state);
    auto cull_queue  = CreateNode<CullQueueTemplate<State>>(*state);

    auto abandon_node = CreateNode<AbandonEntryTemplate<State>>(*state);

    auto consider_skip_mut = CreateNode<ConsiderSkipMutTemplate<State>>(*state);
    auto retry_calibrate = CreateNode<RetryCalibrateTemplate<State>>(*state, *abandon_node);
    auto trim_case = CreateNode<TrimCaseTemplate<State>>(*state, *abandon_node);
    auto calc_score = CreateNode<CalcScoreTemplate<State>>(*state);
    auto apply_det_muts  = CreateNode<ApplyDetMutsTemplate<State>>(*state, *abandon_node);
    auto apply_rand_muts = CreateNode<ApplyRandMutsTemplate<State>>(*state, *abandon_node);

    // actual mutations
    auto bit_flip1 = CreateNode<BitFlip1WithAutoDictBuildTemplate<State>>(*state);
    auto bit_flip_other = CreateNode<BitFlipOtherTemplate<State>>(*state);
    auto byte_flip1 = CreateNode<ByteFlip1WithEffMapBuildTemplate<State>>(*state);
    auto byte_flip_other = CreateNode<ByteFlipOtherTemplate<State>>(*state);
    auto arith = CreateNode<ArithTemplate<State>>(*state);
    auto interest = CreateNode<InterestTemplate<State>>(*state);
    auto user_dict_overwrite = CreateNode<UserDictOverwriteTemplate<State>>(*state);
    auto user_dict_insert = CreateNode<UserDictInsertTemplate<State>>(*state);
    auto auto_dict_overwrite = CreateNode<AutoDictOverwriteTemplate<State>>(*state);
    auto havoc = CreateNode<HavocTemplate<State>>(*state);
    auto splicing = CreateNode<SplicingTemplate<State>>(*state);

    // execution
    auto execute = CreateNode<ExecutePUTTemplate<State>>(*state);

    // updates corresponding to mutations
    auto normal_update = CreateNode<NormalUpdateTemplate<State>>(*state);
    auto construct_auto_dict = CreateNode<ConstructAutoDictTemplate<State>>(*state);
    auto construct_eff_map = CreateNode<ConstructEffMapTemplate<State>>(*state);

    fuzz_loop << (
         cull_queue
      || select_seed
    );

    select_seed << (
         consider_skip_mut
      || retry_calibrate
      || trim_case
      || calc_score
      || apply_det_muts << (
             bit_flip1 << execute << (normal_update || construct_auto_dict)
          || bit_flip_other << execute.HardLink() << normal_update.HardLink()
          || byte_flip1 << execute.HardLink() << (normal_update.HardLink()
                                               || construct_eff_map)
          || byte_flip_other << execute.HardLink() << normal_update.HardLink()
          || arith << execute.HardLink() << normal_update.HardLink()
          || interest << execute.HardLink() << normal_update.HardLink()
          || user_dict_overwrite << execute.HardLink() << normal_update.HardLink()
          || auto_dict_overwrite << execute.HardLink() << normal_update.HardLink()
         )
       || apply_rand_muts << (
               havoc << execute.HardLink() << normal_update.HardLink()
            || splicing << execute.HardLink() << normal_update.HardLink()
          )
       || abandon_node
    );
}

template<class State>
void AFLFuzzerTemplate<State>::OneLoop(void) {
    fuzz_loop();
}

// Do not call non aync-signal-safe functions inside
// because this function can be called during signal handling
template<class State>
void AFLFuzzerTemplate<State>::ReceiveStopSignal(void) {
    state->ReceiveStopSignal();
}

template<class State>
bool AFLFuzzerTemplate<State>::ShouldEnd(void) {
    if (!state) return false;
    return state->stop_soon != 0;
}

} // namespace fuzzuf::algorithm::afl
