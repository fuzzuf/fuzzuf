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

#include "fuzzuf/algorithms/rezzuf_kscheduler/fuzzer.hpp"

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/templates/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/apply_rand_muts.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/havoc.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/load_seed_if_needed.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/option.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/select_seed.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/splicing.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/abandon_entry.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/get_external_seeds.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

hierarflow::HierarFlowNode<void(void), void(void)> BuildFuzzLoop(
    State& state) {
  using fuzzuf::hierarflow::CreateDummyParent;
  using fuzzuf::hierarflow::CreateNode;

  // Create the head node
  auto fuzz_loop = CreateDummyParent<void(void)>();

  // middle nodes(steps done before and after actual mutations)
  auto select_seed = CreateNode<SelectSeed>(state);
  auto cull_queue = CreateNode<fuzzuf::algorithm::afl::routine::other::CullQueueTemplate<State>>(state);

  auto abandon_node = CreateNode<AbandonEntry>(state);

  auto load_seed_if_needed = CreateNode<LoadSeedIfNeeded>(state);
  auto retry_calibrate =
      CreateNode<fuzzuf::algorithm::afl::routine::other::RetryCalibrateTemplate<State>>(state, *abandon_node);
  auto trim_case =
      CreateNode<fuzzuf::algorithm::afl::routine::other::TrimCaseTemplate<State>>(state, *abandon_node);
  auto calc_score = CreateNode<fuzzuf::algorithm::afl::routine::other::CalcScoreTemplate<State>>(state, *abandon_node);
  auto apply_rand_muts = CreateNode<ApplyRandMuts>(state, *abandon_node);

  // actual mutations
  auto havoc = CreateNode<Havoc>(state);
  auto splicing = CreateNode<Splicing>(state);

  // execution
  auto execute = CreateNode<fuzzuf::algorithm::afl::routine::other::ExecutePUTTemplate<State>>(state);

  // updates corresponding to mutations
  auto normal_update = CreateNode<fuzzuf::algorithm::afl::routine::update::NormalUpdateTemplate<State>>(state);

  fuzz_loop << (select_seed || cull_queue);

  cull_queue << (load_seed_if_needed || retry_calibrate || trim_case ||
                  calc_score ||
                  apply_rand_muts << (havoc << execute.HardLink()
                                            << normal_update.HardLink() ||
                                      splicing << execute.HardLink()
                                               << normal_update.HardLink()) ||
                  abandon_node);

  return fuzz_loop;
}

void Fuzzer::OneLoop(void) {
  fuzz_loop();
  if (!ShouldEnd() && state->sync_external_queue) {
    if (state->sync_interval_cnt++ %
        afl::option::GetSyncInterval<State>(*state)) {
      SyncFuzzers();
    }
  }
}

void Fuzzer::SyncFuzzers() {
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

}  // namespace fuzzuf::algorithm::rezzuf
