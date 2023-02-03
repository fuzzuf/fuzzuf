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

#include "fuzzuf/algorithms/mopt/mopt_fuzzer.hpp"

#include "fuzzuf/algorithms/mopt/mopt_hierarflow_routines.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/get_external_seeds.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::algorithm::mopt {

MOptFuzzer::MOptFuzzer(std::unique_ptr<MOptState>&& moved_state)
    : AFLFuzzerTemplate<MOptState>(std::move(moved_state)) {
  BuildFuzzFlow();
}

MOptFuzzer::~MOptFuzzer() {}

void MOptFuzzer::BuildFuzzFlow() {
  {
    using namespace afl::routine::other;
    using namespace afl::routine::mutation;
    using namespace afl::routine::update;

    using hierarflow::CreateDummyParent;
    using hierarflow::CreateNode;

    // head node
    fuzz_loop = CreateDummyParent<void(void)>();

    // middle nodes(steps done before and after actual mutations)
    auto select_seed = CreateNode<SelectSeedTemplate<MOptState>>(*state);
    auto cull_queue = CreateNode<CullQueueTemplate<MOptState>>(*state);

    auto abandon_node = CreateNode<AbandonEntryTemplate<MOptState>>(*state);

    auto consider_skip_mut =
        CreateNode<ConsiderSkipMutTemplate<MOptState>>(*state);
    auto retry_calibrate =
        CreateNode<RetryCalibrateTemplate<MOptState>>(*state, *abandon_node);
    auto trim_case =
        CreateNode<TrimCaseTemplate<MOptState>>(*state, *abandon_node);
    auto calc_score = CreateNode<CalcScoreTemplate<MOptState>>(*state);
    auto apply_det_muts =
        CreateNode<ApplyDetMutsTemplate<MOptState>>(*state, *abandon_node);
    auto apply_rand_muts =
        CreateNode<ApplyRandMutsTemplate<MOptState>>(*state, *abandon_node);

    // actual mutations
    auto bit_flip1 =
        CreateNode<BitFlip1WithAutoDictBuildTemplate<MOptState>>(*state);
    auto bit_flip_other = CreateNode<BitFlipOtherTemplate<MOptState>>(*state);
    auto byte_flip1 =
        CreateNode<ByteFlip1WithEffMapBuildTemplate<MOptState>>(*state);
    auto byte_flip_other = CreateNode<ByteFlipOtherTemplate<MOptState>>(*state);
    auto arith = CreateNode<ArithTemplate<MOptState>>(*state);
    auto interest = CreateNode<InterestTemplate<MOptState>>(*state);
    auto user_dict_overwrite =
        CreateNode<UserDictOverwriteTemplate<MOptState>>(*state);
    auto user_dict_insert =
        CreateNode<UserDictInsertTemplate<MOptState>>(*state);
    auto auto_dict_overwrite =
        CreateNode<AutoDictOverwriteTemplate<MOptState>>(*state);

    // MOpt-specific mutations
    using fuzzuf::algorithm::mopt::routine::mutation::MOptHavoc;
    using fuzzuf::algorithm::mopt::routine::mutation::MOptSplicing;

    auto havoc = CreateNode<MOptHavoc>(*state);
    auto splicing = CreateNode<MOptSplicing>(*state);

    // execution
    auto execute = CreateNode<ExecutePUTTemplate<MOptState>>(*state);

    // updates corresponding to mutations
    auto normal_update = CreateNode<NormalUpdateTemplate<MOptState>>(*state);
    auto construct_auto_dict =
        CreateNode<ConstructAutoDictTemplate<MOptState>>(*state);
    auto construct_eff_map =
        CreateNode<ConstructEffMapTemplate<MOptState>>(*state);

    // MOpt-specific nodes
    using fuzzuf::algorithm::mopt::routine::other::CheckPacemakerThreshold;
    using fuzzuf::algorithm::mopt::routine::other::MOptUpdate;
    using fuzzuf::algorithm::mopt::routine::other::SavePacemakerHitCnt;

    auto check_pacemaker =
        CreateNode<CheckPacemakerThreshold>(*state, *apply_rand_muts);
    auto update_mopt = CreateNode<MOptUpdate>(*state);
    auto save_pacemaker = CreateNode<SavePacemakerHitCnt>(*state);

    fuzz_loop << (cull_queue || select_seed);

    select_seed << (consider_skip_mut || retry_calibrate || trim_case ||
                    calc_score || check_pacemaker ||
                    apply_det_muts
                        << (bit_flip1
                                << execute
                                << (normal_update || construct_auto_dict) ||
                            bit_flip_other << execute.HardLink()
                                           << normal_update.HardLink() ||
                            byte_flip1 << execute.HardLink()
                                       << (normal_update.HardLink() ||
                                           construct_eff_map) ||
                            byte_flip_other << execute.HardLink()
                                            << normal_update.HardLink() ||
                            arith << execute.HardLink()
                                  << normal_update.HardLink() ||
                            interest << execute.HardLink()
                                     << normal_update.HardLink() ||
                            user_dict_overwrite << execute.HardLink()
                                                << normal_update.HardLink() ||
                            auto_dict_overwrite << execute.HardLink()
                                                << normal_update.HardLink()) ||
                    save_pacemaker ||
                    apply_rand_muts << (havoc << execute.HardLink()
                                              << normal_update.HardLink() ||
                                        splicing << execute.HardLink()
                                                 << normal_update.HardLink()) ||
                    abandon_node || update_mopt);
  }
}

void MOptFuzzer::OneLoop(void) {
  fuzz_loop();
  if (!ShouldEnd() && state->sync_external_queue) {
    if (state->sync_interval_cnt++ %
        afl::option::GetSyncInterval<MOptState>(*state)) {
      SyncFuzzers();
    }
  }
}

void MOptFuzzer::SyncFuzzers() {
  for (const auto& seed : utils::GetExternalSeeds(
           state->setting->out_dir.parent_path(), state->sync_id, true)) {
    feedback::ExitStatusFeedback exit_status;
    feedback::InplaceMemoryFeedback inp_feed =
        state->RunExecutorWithClassifyCounts(
            &*seed.begin(), std::distance(seed.begin(), seed.end()),
            exit_status);
    if (exit_status.exit_reason != feedback::PUTExitReasonType::FAULT_TMOUT) {
      if (state->SaveIfInteresting(&*seed.begin(),
                                   std::distance(seed.begin(), seed.end()),
                                   inp_feed, exit_status)) {
        state->queued_discovered++;
      }
    }
  }
}

}  // namespace fuzzuf::algorithm::mopt
