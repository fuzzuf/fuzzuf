/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl_kscheduler/fuzzer.hpp"

#include "fuzzuf/algorithms/afl_kscheduler/option.hpp"
#include "fuzzuf/utils/get_external_seeds.hpp"

namespace fuzzuf::algorithm::afl {
template<>
hierarflow::HierarFlowNode<void(void), void(void)> BuildAFLFuzzLoop(
  afl_kscheduler::AFLKSchedulerState &state
) {
  using namespace fuzzuf::algorithm::afl::routine::other;
  using namespace fuzzuf::algorithm::afl::routine::mutation;
  using namespace fuzzuf::algorithm::afl::routine::update;

  using fuzzuf::hierarflow::CreateDummyParent;
  using fuzzuf::hierarflow::CreateNode;
  using State = afl_kscheduler::AFLKSchedulerState;
  // Create the head node
  auto fuzz_loop = CreateDummyParent<void(void)>();

  // middle nodes(steps done before and after actual mutations)
  auto select_seed = CreateNode<SelectSeedTemplate<State>>(state);
  auto cull_queue = CreateNode<CullQueueTemplate<State>>(state);

  auto abandon_node = CreateNode<AbandonEntryTemplate<State>>(state);

  auto consider_skip_mut = CreateNode<ConsiderSkipMutTemplate<State>>(state);
  auto retry_calibrate =
      CreateNode<RetryCalibrateTemplate<State>>(state, *abandon_node);
  auto trim_case = CreateNode<TrimCaseTemplate<State>>(state, *abandon_node);
  auto calc_score = CreateNode<CalcScoreTemplate<State>>(state, *abandon_node);
  auto apply_det_muts =
      CreateNode<ApplyDetMutsTemplate<State>>(state, *abandon_node);
  auto apply_rand_muts =
      CreateNode<ApplyRandMutsTemplate<State>>(state, *abandon_node);

  // actual mutations
  auto bit_flip1 = CreateNode<BitFlip1WithAutoDictBuildTemplate<State>>(state);
  auto bit_flip_other = CreateNode<BitFlipOtherTemplate<State>>(state);
  auto byte_flip1 = CreateNode<ByteFlip1WithEffMapBuildTemplate<State>>(state);
  auto byte_flip_other = CreateNode<ByteFlipOtherTemplate<State>>(state);
  auto arith = CreateNode<ArithTemplate<State>>(state);
  auto interest = CreateNode<InterestTemplate<State>>(state);
  auto user_dict_overwrite =
      CreateNode<UserDictOverwriteTemplate<State>>(state);
  auto user_dict_insert = CreateNode<UserDictInsertTemplate<State>>(state);
  auto auto_dict_overwrite =
      CreateNode<AutoDictOverwriteTemplate<State>>(state);
  auto havoc = CreateNode<HavocTemplate<State>>(state);
  auto splicing = CreateNode<SplicingTemplate<State>>(state);

  // execution
  auto execute = CreateNode<ExecutePUTTemplate<State>>(state);
  auto execute_splice = CreateNode<ExecutePUTTemplate<State>>(state,true);

  // updates corresponding to mutations
  auto normal_update = CreateNode<NormalUpdateTemplate<State>>(state,false);
  auto construct_auto_dict =
      CreateNode<ConstructAutoDictTemplate<State>>(state);
  auto construct_eff_map = CreateNode<ConstructEffMapTemplate<State>>(state);

  fuzz_loop << ( select_seed || cull_queue );

  cull_queue << ( consider_skip_mut || retry_calibrate || trim_case ||
                  calc_score ||
                  apply_det_muts
                      << (bit_flip1 << execute
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
                          user_dict_insert << execute.HardLink()
                                           << normal_update.HardLink() ||
                          auto_dict_overwrite << execute.HardLink()
                                              << normal_update.HardLink()) ||
                  apply_rand_muts << (havoc << execute.HardLink()
                                            << normal_update.HardLink() ||
                                      splicing << execute_splice.HardLink()
                                               << normal_update.HardLink()) ||
                  abandon_node);

  return fuzz_loop;
}

}

namespace fuzzuf::algorithm::afl_kscheduler {

AFLKSchedulerFuzzer::AFLKSchedulerFuzzer(std::unique_ptr<AFLKSchedulerState>&& state)
  : afl::AFLFuzzerTemplate<AFLKSchedulerState>(std::move(state)),
    fuzz_loop(BuildAFLFuzzLoop(*AFLFuzzerTemplate<AFLKSchedulerState>::state)) {
    
    }

void AFLKSchedulerFuzzer::OneLoop(void) {
  fuzz_loop();
  if (!ShouldEnd() && state->sync_external_queue) {
    if (state->sync_interval_cnt++ %
        afl::option::GetSyncInterval<AFLKSchedulerState>(*state)) {
      SyncFuzzers();
    }
  }
}
void AFLKSchedulerFuzzer::SyncFuzzers() {
  for (const auto &seed : utils::GetExternalSeeds(
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

}  // namespace fuzzuf::algorithm::afl_kscheduler
