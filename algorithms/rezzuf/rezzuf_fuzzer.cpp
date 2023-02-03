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

#include "fuzzuf/algorithms/rezzuf/rezzuf_fuzzer.hpp"

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_option.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/get_external_seeds.hpp"

namespace fuzzuf::algorithm::rezzuf {

hierarflow::HierarFlowNode<void(void), void(void)> BuildFuzzLoop(
    RezzufState& state) {
  using rezzuf::routine::LoadSeedIfNeeded;
  using rezzuf::routine::RezzufAbandonEntry;
  using rezzuf::routine::RezzufApplyRandMuts;
  using rezzuf::routine::RezzufHavoc;
  using rezzuf::routine::RezzufSelectSeed;
  using rezzuf::routine::RezzufSplicing;

  using namespace fuzzuf::algorithm::afl::routine::other;
  using namespace fuzzuf::algorithm::afl::routine::update;

  using fuzzuf::hierarflow::CreateDummyParent;
  using fuzzuf::hierarflow::CreateNode;

  // Create the head node
  auto fuzz_loop = CreateDummyParent<void(void)>();

  // middle nodes(steps done before and after actual mutations)
  auto select_seed = CreateNode<RezzufSelectSeed>(state);
  auto cull_queue = CreateNode<CullQueueTemplate<RezzufState>>(state);

  auto abandon_node = CreateNode<RezzufAbandonEntry>(state);

  auto load_seed_if_needed = CreateNode<LoadSeedIfNeeded>();
  auto retry_calibrate =
      CreateNode<RetryCalibrateTemplate<RezzufState>>(state, *abandon_node);
  auto trim_case =
      CreateNode<TrimCaseTemplate<RezzufState>>(state, *abandon_node);
  auto calc_score = CreateNode<CalcScoreTemplate<RezzufState>>(state);
  auto apply_rand_muts = CreateNode<RezzufApplyRandMuts>(state, *abandon_node);

  // actual mutations
  auto havoc = CreateNode<RezzufHavoc>(state);
  auto splicing = CreateNode<RezzufSplicing>(state);

  // execution
  auto execute = CreateNode<ExecutePUTTemplate<RezzufState>>(state);

  // updates corresponding to mutations
  auto normal_update = CreateNode<NormalUpdateTemplate<RezzufState>>(state);

  fuzz_loop << (cull_queue || select_seed);

  select_seed << (load_seed_if_needed || retry_calibrate || trim_case ||
                  calc_score ||
                  apply_rand_muts << (havoc << execute.HardLink()
                                            << normal_update.HardLink() ||
                                      splicing << execute.HardLink()
                                               << normal_update.HardLink()) ||
                  abandon_node);

  return fuzz_loop;
}

void RezzufFuzzer::OneLoop(void) {
  fuzz_loop();
  if (!ShouldEnd() && state->sync_external_queue) {
    if (state->sync_interval_cnt++ %
        afl::option::GetSyncInterval<RezzufState>(*state)) {
      SyncFuzzers();
    }
  }
}

void RezzufFuzzer::SyncFuzzers() {
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
