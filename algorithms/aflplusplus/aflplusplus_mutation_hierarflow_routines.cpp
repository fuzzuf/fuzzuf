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
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_mutation_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/aflplusplus/aflplusplus_havoc.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_testcase.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

using AFLplusplusTestcase = aflplusplus::AFLplusplusTestcase;

// explicit specialization
template <>
AFLMutCalleeRef<AFLplusplusState> HavocTemplate<AFLplusplusState>::operator()(
    AFLMutatorTemplate<AFLplusplusState>& mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto& state = this->state;

  s32 stage_max_multiplier;
  if (state.doing_det)
    stage_max_multiplier = option::GetHavocCyclesInit(state);
  else
    stage_max_multiplier = option::GetHavocCycles(state);

  using afl::dictionary::AFLDictData;

  if (this->DoHavoc(
          mutator, *state.havoc_optimizer,
          aflplusplus::havoc::AFLplusplusCustomCases<AFLplusplusState>(state),
          "more_havoc", "more_havoc", state.orig_perf, stage_max_multiplier,
          option::STAGE_HAVOC)) {
    this->SetResponseValue(true);
    return this->GoToParent();
  }

  return this->GoToDefaultNext();
}

template <>
AFLMutCalleeRef<AFLplusplusState>
SplicingTemplate<AFLplusplusState>::operator()(
    AFLMutatorTemplate<AFLplusplusState>& mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto& state = this->state;

  if (!state.use_splicing || state.setting->ignore_finds) {
    return this->GoToDefaultNext();
  }

  u32 splice_cycle = 0;
  while (splice_cycle++ < option::GetSpliceCycles(state) &&
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

    auto& target_case = *state.case_queue[tid];
    state.splicing_with = tid;

    /* Read the testcase into a new buffer. */

    target_case.input->Load();
    bool success = mutator.Splice(*target_case.input);
    target_case.input->Unload();

    if (!success) {
      continue;
    }

    using afl::dictionary::AFLDictData;

    if (this->DoHavoc(
            mutator, *state.havoc_optimizer,
            aflplusplus::havoc::AFLplusplusCustomCases<AFLplusplusState>(state),
            utils::StrPrintf("more_splice %u", splice_cycle), "more_splice",
            state.orig_perf, option::GetSpliceHavoc(state),
            option::STAGE_SPLICE)) {
      this->SetResponseValue(true);
      return this->GoToParent();
    }

    mutator.RestoreSplice();
  }

  optimizer::Store::GetInstance().Set(optimizer::keys::LastSpliceCycle,
                                      splice_cycle);

  return this->GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::afl::routine::mutation
