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

#include "fuzzuf/algorithms/rezzuf/rezzuf_hierarflow_routines.hpp"

#include <limits>

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_util.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_state.hpp"
#include "fuzzuf/algorithms/rezzuf/rezzuf_testcase.hpp"

namespace fuzzuf::algorithm::rezzuf::routine {

// FIXME: some of Rezzuf's HierarFlowRoutines such as RezzufSelectSeed and those
// of AFL++ are almost the same. These should be unified into one template
// struct in future refactoring. The unification requires a bit large diff due
// to the following reasons:
// 1. AFL++ reuses `afl::BuildAFLFuzzFlow` in building its fuzz_loop by
// overriding some HierarFlowRoutines of AFL with explicit specialization.
// 2. AFL++ and Rezzuf use different State structs: AFLplusplusState and
// RezzufState. And there is no inheritance between them. To reuse AFL++'s
// HierarFlowRoutines in Rezzuf, they should be defined as independent structs,
// not as the explicit specialization of AFL. To this end, first AFL++ should
// stop using `afl::BuildAFLFuzzFlow` and define its own `BuildFuzzFlow`
// function.

RezzufSelectSeed::RezzufSelectSeed(RezzufState &state) : state(state) {}

utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
RezzufSelectSeed::operator()(void) {
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
  state.current_entry = (*state.alias_probability)();
  auto &testcase = state.case_queue[state.current_entry];
  this->CallSuccessors(testcase);

  return this->GoToDefaultNext();
}

LoadSeedIfNeeded::LoadSeedIfNeeded() {}

// Seed should be loaded on memory when calibration or trimming is needed
AFLMidCalleeRef<RezzufState> LoadSeedIfNeeded::operator()(
    std::shared_ptr<RezzufTestcase> testcase) {
  if (testcase->cal_failed > 0 || !testcase->trim_done) {
    testcase->input->Load();
  }

  return this->GoToDefaultNext();
}

RezzufApplyRandMuts::RezzufApplyRandMuts(
    RezzufState &state, AFLMidCalleeRef<RezzufState> abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

AFLMidCalleeRef<RezzufState> RezzufApplyRandMuts::operator()(
    std::shared_ptr<RezzufTestcase> testcase) {
  // We no longer modify this testcase.
  // So we can reload the file with mmap.
  testcase->input->LoadByMmap();  // no need to Unload

  auto mutator = RezzufMutator(*testcase->input, state);

  // call probablistic mutations
  // if they return true, then we should go to abandon_entry
  auto should_abandon_entry = this->CallSuccessors(mutator);
  if (should_abandon_entry) {
    this->SetResponseValue(true);
    return abandon_entry;
  }

  return this->GoToDefaultNext();
}

RezzufHavoc::RezzufHavoc(RezzufState &state)
    : afl::routine::mutation::HavocBaseTemplate<RezzufState>(state) {}

AFLMutCalleeRef<RezzufState> RezzufHavoc::operator()(RezzufMutator &mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto &state = this->state;

  s32 stage_max_multiplier = afl::option::GetHavocCycles(state);

  if (this->DoHavoc(
          mutator, *state.havoc_optimizer,
          aflplusplus::havoc::AFLplusplusCustomCases<RezzufState>(state),
          "more_havoc", "more_havoc", state.orig_perf, stage_max_multiplier,
          afl::option::STAGE_HAVOC)) {
    this->SetResponseValue(true);
    return this->GoToParent();
  }

  return this->GoToDefaultNext();
}

RezzufSplicing::RezzufSplicing(RezzufState &state)
    : afl::routine::mutation::HavocBaseTemplate<RezzufState>(state) {}

AFLMutCalleeRef<RezzufState> RezzufSplicing::operator()(
    RezzufMutator &mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto &state = this->state;

  if (!state.use_splicing || state.setting->ignore_finds) {
    return this->GoToDefaultNext();
  }

  u32 splice_cycle = 0;
  while (splice_cycle++ < afl::option::GetSpliceCycles(state) &&
         state.queued_paths > 1 && mutator.GetSource().GetLen() > 1) {
    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    u32 tid;
    do {
      using afl::util::UR;
      tid = UR(state.queued_paths, state.rand_fd);
    } while (tid == state.current_entry);

    /* Make sure that the target has a reasonable length. */

    while (tid < state.case_queue.size()) {
      if (state.case_queue[tid]->input->GetLen() >= 2 &&
          tid != state.current_entry)
        break;

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

    if (this->DoHavoc(
            mutator, *state.havoc_optimizer,
            aflplusplus::havoc::AFLplusplusCustomCases<RezzufState>(state),
            utils::StrPrintf("more_splice %u", splice_cycle), "more_splice",
            state.orig_perf, afl::option::GetSpliceHavoc(state),
            afl::option::STAGE_SPLICE)) {
      this->SetResponseValue(true);
      return this->GoToParent();
    }

    mutator.RestoreSplice();
  }

  return this->GoToDefaultNext();
}

RezzufAbandonEntry::RezzufAbandonEntry(RezzufState &state) : state(state) {}

AFLMidCalleeRef<RezzufState> RezzufAbandonEntry::operator()(
    std::shared_ptr<RezzufTestcase> testcase) {
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

}  // namespace fuzzuf::algorithm::rezzuf::routine
