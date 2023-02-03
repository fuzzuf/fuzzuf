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

#include "fuzzuf/algorithms/mopt/mopt_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option_get_splice_cycles.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::mopt::routine {

namespace other {

using fuzzuf::optimizer::MOptMode;
using mopt::option::MOptTag;

MOptUpdate::MOptUpdate(MOptState &state) : state(state) {}

MOptMidCalleeRef MOptUpdate::operator()(
    [[maybe_unused]] std::shared_ptr<MOptTestcase> testcase) {
  // retrive optimizer values
  auto last_splice_cycle = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::LastSpliceCycle, true);
  auto havoc_operator_finds = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::HavocOperatorFinds, true);
  auto selected_case_histogram = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::SelectedCaseHistogram, true);

  auto &mopt = state.mopt;

  // update havoc_operator_finds
  for (size_t i = 0; i < havoc_operator_finds.size(); i++) {
    mopt->accum_havoc_operator_finds[mopt->mode][i] += havoc_operator_finds[i];
    mopt->accum_selected_case_histogram[mopt->mode][i] +=
        selected_case_histogram[i];
  }

  if (last_splice_cycle >= afl::option::GetSpliceCycles(state)) {
    state.UpdateSpliceCycles();
  }

  if (mopt->pacemaker_mode) {
    u64 hit_cnt = state.queued_paths + state.unique_crashes;

    if (unlikely(hit_cnt > hit_cnt * option::GetLimitTimeBound<MOptTag>() +
                               mopt->pacemaker_hit_cnt)) {
      mopt->pacemaker_hit_cnt = 0;
      mopt->pacemaker_mode = false;
    }
  }

  auto new_testcases = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::NewTestcases, true);

  // pilot mode (update local best)
  if (mopt->mode == MOptMode::PilotMode) {
    if (unlikely(new_testcases > mopt::option::GetPeriodPilot<MOptTag>())) {
      auto last_havoc_finds = fuzzuf::optimizer::Store::GetInstance().Get(
          fuzzuf::optimizer::keys::LastHavocFinds, true);
      mopt->SetSwarmFitness(last_havoc_finds / new_testcases);

      for (size_t i = 0; i < selected_case_histogram.size(); i++) {
        double score = 0.0;
        if (mopt->accum_selected_case_histogram[MOptMode::CoreMode][i] > 0) {
          score = mopt->accum_havoc_operator_finds[MOptMode::CoreMode][i] /
                  mopt->accum_selected_case_histogram[MOptMode::CoreMode][i];
        }
        mopt->SetScore(i, score);
      }
      mopt->UpdateLocalBest();
      mopt->accum_havoc_operator_finds[MOptMode::CoreMode].fill(0);
      mopt->accum_selected_case_histogram[MOptMode::CoreMode].fill(0);

      if (mopt->NextSwarmIdx() == 0) {  // all swarms are visited
        mopt->UpdateBestSwarmIdx();
        mopt->accum_havoc_operator_finds[MOptMode::CoreMode].fill(0);
        mopt->accum_selected_case_histogram[MOptMode::CoreMode].fill(0);
        mopt->mode = MOptMode::CoreMode;
      }
    }
  }

  // core mode (update global best)
  if (mopt->mode == MOptMode::CoreMode) {
    if (unlikely(new_testcases > mopt::option::GetPeriodCore<MOptTag>())) {
      mopt->UpdateGlobalBest();
      mopt->accum_havoc_operator_finds[MOptMode::PilotMode].fill(0);
      mopt->accum_selected_case_histogram[MOptMode::PilotMode].fill(0);
      mopt->mode = MOptMode::PilotMode;
    }
  }

  return this->GoToDefaultNext();
}

CheckPacemakerThreshold::CheckPacemakerThreshold(MOptState &state,
                                                 MOptMidCalleeRef abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

MOptMidCalleeRef CheckPacemakerThreshold::operator()(
    [[maybe_unused]] std::shared_ptr<MOptTestcase> testcase) {
  auto &mopt = state.mopt;
  u64 cur_ms_lv = fuzzuf::utils::GetCurTimeMs();
  if (!(mopt->pacemaker_mode == false &&
        ((cur_ms_lv - state.last_path_time < state.setting->mopt_limit_time) ||
         (state.last_crash_time != 0 &&
          cur_ms_lv - state.last_crash_time < state.setting->mopt_limit_time) ||
         (state.last_path_time == 0)))) {
    mopt->pacemaker_mode = true;
    return abandon_entry;
  }
  return this->GoToDefaultNext();
}

SavePacemakerHitCnt::SavePacemakerHitCnt(MOptState &state) : state(state) {}

MOptMidCalleeRef SavePacemakerHitCnt::operator()(
    [[maybe_unused]] std::shared_ptr<MOptTestcase> testcase) {
  auto &mopt = state.mopt;

  if (mopt->pacemaker_mode == true && unlikely(mopt->pacemaker_hit_cnt == 0)) {
    mopt->pacemaker_hit_cnt = state.queued_paths + state.unique_crashes;
    state.UpdateSpliceCycles();
  }

  return this->GoToDefaultNext();
}

}  // namespace other

namespace mutation {

MOptHavoc::MOptHavoc(MOptState &state) : HavocBaseTemplate<MOptState>(state) {}

MOptMutCalleeRef MOptHavoc::operator()(MOptMutator &mutator) {
  // Declare the alias just to omit "this->" in this function.
  auto &state = this->state;

  s32 stage_max_multiplier;
  if (state.doing_det)
    stage_max_multiplier = afl::option::GetHavocCyclesInit(state);
  else
    stage_max_multiplier = afl::option::GetHavocCycles(state);

  using afl::dictionary::AFLDictData;

  if (this->DoHavoc(
          mutator, *state.havoc_optimizer,
          [](int, u8 *&, u32 &, const std::vector<AFLDictData> &,
             const std::vector<AFLDictData> &) {},
          "MOpt-havoc", "MOpt-havoc", state.orig_perf, stage_max_multiplier,
          afl::option::STAGE_HAVOC)) {
    this->SetResponseValue(true);
    return this->GoToParent();
  }

  return this->GoToDefaultNext();
}

MOptSplicing::MOptSplicing(MOptState &state)
    : HavocBaseTemplate<MOptState>(state) {}

MOptMutCalleeRef MOptSplicing::operator()(MOptMutator &mutator) {
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

    using afl::dictionary::AFLDictData;

    if (this->DoHavoc(
            mutator, *state.havoc_optimizer,
            [](int, u8 *&, u32 &, const std::vector<AFLDictData> &,
               const std::vector<AFLDictData> &) {},
            fuzzuf::utils::StrPrintf("MOpt-splice %u", splice_cycle),
            "MOpt-splice", state.orig_perf, afl::option::GetSpliceHavoc(state),
            afl::option::STAGE_SPLICE)) {
      this->SetResponseValue(true);
      return this->GoToParent();
    }

    mutator.RestoreSplice();
  }
  fuzzuf::optimizer::Store::GetInstance().Set(
      fuzzuf::optimizer::keys::LastSpliceCycle, splice_cycle);

  return this->GoToDefaultNext();
}

}  // namespace mutation

}  // namespace fuzzuf::algorithm::mopt::routine
