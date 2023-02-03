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
#include "fuzzuf/algorithms/aflfast/aflfast_other_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_testcase.hpp"

namespace fuzzuf::algorithm::afl::routine::other {

using AFLFastState = aflfast::AFLFastState;
using AFLFastTestcase = aflfast::AFLFastTestcase;

// explicit specialization
template <>
AFLMidCalleeRef<AFLFastState> ApplyDetMutsTemplate<AFLFastState>::operator()(
    std::shared_ptr<AFLFastTestcase> testcase) {
  // We no longer modify this testcase.
  // So we can reload the file with mmap.
  testcase->input->LoadByMmap();  // no need to Unload

  if (state.orig_perf == 0 && state.queued_paths > 10) {
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

  if (state.master_max &&
      (testcase->exec_cksum % state.master_max) != state.master_id - 1) {
    state.doing_det = false;
    return this->GoToDefaultNext();
  }

  state.doing_det = true;

  auto mutator = AFLMutatorTemplate<AFLFastState>(*testcase->input, state);

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
AFLMidCalleeRef<AFLFastState> AbandonEntryTemplate<AFLFastState>::operator()(
    std::shared_ptr<AFLFastTestcase> testcase) {
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

}  // namespace fuzzuf::algorithm::afl::routine::other
