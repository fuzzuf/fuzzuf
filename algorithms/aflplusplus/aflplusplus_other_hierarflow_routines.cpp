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

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_other_hierarflow_routines.hpp"

#include <memory>
#include <numeric>

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_testcase.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_util.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::afl::routine::other {

using AFLplusplusState = aflplusplus::AFLplusplusState;
using AFLplusplusTestcase = aflplusplus::AFLplusplusTestcase;

// explicit specialization
template <>
AFLMidCalleeRef<AFLplusplusState>
ApplyDetMutsTemplate<AFLplusplusState>::operator()(
    std::shared_ptr<AFLplusplusTestcase> testcase) {
  // We no longer modify this testcase.
  // So we can reload the file with mmap.
  testcase->input->LoadByMmap();  // no need to Unload

  if (!state.orig_perf && state.queued_paths > 10) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  /* Skip right away if -d is given, if it has not been chosen sufficiently
     often to warrant the expensive deterministic stage (fuzz_level), or
     if it has gone through deterministic testing in earlier, resumed runs
     (passed_det). */

  if (state.skip_deterministic ||
      ((!testcase->passed_det) &&
       state.orig_perf <
           (testcase->depth * 30 <= option::GetHavocMaxMult(state) * 100
                ? testcase->depth * 30
                : option::GetHavocMaxMult(state) * 100)) ||
      testcase->passed_det) {
    state.doing_det = false;
    return this->GoToDefaultNext();
  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (state.orig_perf == 0 && state.queued_paths > 10) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  state.doing_det = true;

  auto mutator = AFLMutatorTemplate<AFLplusplusState>(*testcase->input, state);

  state.stage_val_type = option::STAGE_VAL_NONE;

  // this will be required in dictionary construction and eff_map construction
  state.queue_cur_exec_cksum = testcase->exec_cksum;

  // call deterministic mutations
  // if they return true, then we should go to abandon_entry
  auto should_abandon_entry = this->CallSuccessors(mutator);

  if (should_abandon_entry) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  // NOTE: "if (!testcase->passed_det)" seems unnecessary to me
  // because passed_det == 0 always holds here
  if (!testcase->passed_det) state.MarkAsDetDone(*testcase);

  return this->GoToDefaultNext();
}

// explicit specialization
template <>
AFLMidCalleeRef<AFLplusplusState>
AbandonEntryTemplate<AFLplusplusState>::operator()(
    std::shared_ptr<AFLplusplusTestcase> testcase) {
  state.splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!state.stop_soon && !testcase->cal_failed && !testcase->WasFuzzed()) {
    state.pending_not_fuzzed--;
    if (testcase->favored) state.pending_favored--;
  }

  testcase->fuzz_level++;

  testcase->input->Unload();

  // ReponseValue should be set in previous steps, so do nothing here
  return this->GoToDefaultNext();
}

// explicit specialization
template <>
utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
SelectSeedTemplate<AFLplusplusState>::operator()(void) {
  static size_t runs_in_current_cycle = static_cast<size_t>(-1);
  if (state.queue_cycle == 0 ||
      runs_in_current_cycle > state.case_queue.size()) {
    state.queue_cycle++;
    runs_in_current_cycle = static_cast<size_t>(-1);
    // state.current_entry = state.seek_to; // seek_to is used in resume mode
    state.seek_to = 0;
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

#if 0
        if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
            sync_fuzzers(use_argv);
#endif

    DEBUG_ASSERT(state.current_entry < state.case_queue.size());
  }

  // possible intentional overflow
  runs_in_current_cycle++;

  if (state.prev_queued_items < state.case_queue.size()) {
    // we have new queue entries since the last run, recreate alias table
    state.prev_queued_items = state.case_queue.size();
    aflplusplus::util::CreateAliasTable(state);
  }

  // get the testcase indexed by state.current_entry and start mutations
  state.current_entry = (*state.alias_probability)();
  auto &testcase = state.case_queue[state.current_entry];
  this->CallSuccessors(testcase);

#if 0
    auto skipped_fuzz = CallSuccessors(testcase);

    if (!state.stop_soon && state.sync_id && !skipped_fuzz) {
      if (!(state.sync_interval_cnt++ % option::GetSyncInterval(state)))
        SyncFuzzers(use_argv);
    }
#endif

  return this->GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::afl::routine::other
