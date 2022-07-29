#include "fuzzuf/algorithms/mopt/mopt_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/mopt/mopt_optimizer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option_get_splice_cycles.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::mopt::routine {

namespace other {

using mopt::option::MOptTag;

MOptUpdate::MOptUpdate(MOptState &state) : state(state) {}

MOptMidCalleeRef MOptUpdate::operator()(
    [[maybe_unused]] std::shared_ptr<MOptTestcase> testcase) {
  // retrive optimizer values
  auto last_splice_cycle = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::LastSpliceCycle, true);
  auto havoc_operator_finds = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::HavocOperatorFinds, true);

  auto &mopt = state.mopt;

  // update havoc_operator_finds
  for (size_t i = 0; i < havoc_operator_finds.size(); i++) {
    mopt->havoc_operator_finds[state.core_mode ? 1 : 0][i] +=
        havoc_operator_finds[i];
  }

  if (last_splice_cycle >= afl::option::GetSpliceCycles(state)) {
    state.UpdateSpliceCycles();
  }

  if (state.pacemaker_mode) {
    // TODO
  }

  auto new_testcases = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::NewTestcases, true);
  auto selected_case_histogram = fuzzuf::optimizer::Store::GetInstance().Get(
      fuzzuf::optimizer::keys::SelectedCaseHistogram, true);

  // pilot mode (update local best)
  if (!state.core_mode) {
    if (unlikely(new_testcases > mopt::option::GetPeriodPilot<MOptTag>())) {
      for (size_t i = 0; i < selected_case_histogram.size(); i++) {
        double score = 0.0;
        if (selected_case_histogram[i] > 0) {
          score = (mopt->havoc_operator_finds[0][i] +
                   mopt->havoc_operator_finds[1][i]) /
                  selected_case_histogram[i];
        }
        mopt->SetScore(i, score);
      }
      mopt->UpdateLocalBest();

      if (mopt->IncrementSwarmIdx()) {  // all swarms are visited
        state.core_mode = true;
      }
    }
  }

  // core mode (update global best)
  if (state.core_mode) {
    if (unlikely(new_testcases > mopt::option::GetPeriodCore<MOptTag>())) {
      mopt->UpdateGlobalBest();
      state.core_mode = false;
    }
  }

  return this->GoToDefaultNext();
}

CheckPacemakerThreshold::CheckPacemakerThreshold(MOptState &state,
                                                 MOptMidCalleeRef abandon_entry)
    : state(state), abandon_entry(abandon_entry) {}

MOptMidCalleeRef CheckPacemakerThreshold::operator()(
    [[maybe_unused]] std::shared_ptr<MOptTestcase> testcase) {
  u64 cur_ms_lv = fuzzuf::utils::GetCurTimeMs();
  if (!(state.pacemaker_mode == false &&
        ((cur_ms_lv - state.last_path_time < state.setting->mopt_limit_time) ||
         (state.last_crash_time != 0 &&
          cur_ms_lv - state.last_crash_time < state.setting->mopt_limit_time) ||
         (state.last_path_time == 0)))) {
    state.pacemaker_mode = true;
    return abandon_entry;
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
          mutator, *state.mutop_optimizer,
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
            mutator, *state.mutop_optimizer,
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
