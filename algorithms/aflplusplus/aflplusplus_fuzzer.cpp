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

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_fuzzer.hpp"

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_option.hpp"
#include "fuzzuf/utils/get_external_seeds.hpp"

namespace fuzzuf::algorithm::aflplusplus {
void AFLplusplusFuzzer::OneLoop(void) {
  fuzz_loop();
  if (!ShouldEnd() && state->sync_external_queue) {
    if (state->sync_interval_cnt++ %
        afl::option::GetSyncInterval<AFLplusplusState>(*state)) {
      SyncFuzzers();
    }
  }
}
void AFLplusplusFuzzer::SyncFuzzers() {
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
}  // namespace fuzzuf::algorithm::aflplusplus
