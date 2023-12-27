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

#include "fuzzuf/algorithms/rezzuf_kscheduler/select_seed.hpp"

#include <limits>

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_option.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_util.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/state.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/testcase.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/option.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
SelectSeed::operator()(void) {
  FUZZUF_ALGORITHM_AFL_ENTER_HIERARFLOW_NODE
  static size_t runs_in_current_cycle = std::numeric_limits<size_t>::max();

  if (state.queue_cycle == 0 ||
      runs_in_current_cycle > state.case_queue.size()) {
    state.queue_cycle++;
    state.cur_skipped_paths = 0;

    state.ShowStats();
    if (state.not_on_tty) {
      ACTF("Entering queue cycle %llu.", state.queue_cycle);
      fflush(stdout);
    }

    /* If we had a full queue cycle with no new finds, try
       recombination strategies next. */

    if (state.queued_paths == prev_queued) {
      if (state.use_splicing)
        state.cycles_wo_finds++;
      else
        state.use_splicing = true;
    } else
      state.cycles_wo_finds = 0;

    prev_queued = state.queued_paths;

    runs_in_current_cycle = 0;
  } else {
    runs_in_current_cycle++;
  }

  if (state.prev_queued_items < state.case_queue.size()) {
    // we have new queue entries since the last run, recreate alias table
    state.prev_queued_items = state.case_queue.size();
    aflplusplus::util::CreateAliasTable(state);
  }

  // get the testcase indexed by state.current_entry and start mutations
  using Tag = typename State::Tag;
  if constexpr ( !afl::option::EnableKScheduler< Tag >() ) {
    state.current_entry = (*state.alias_probability)();
    auto &testcase = state.case_queue[state.current_entry];
    this->CallSuccessors(testcase);
  }

  return this->GoToDefaultNext();
}

}

