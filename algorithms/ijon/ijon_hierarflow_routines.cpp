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

#include "fuzzuf/algorithms/ijon/ijon_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/ijon/ijon_havoc.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"
#include "fuzzuf/logger/stdout_logger.hpp"

namespace fuzzuf::algorithm::ijon::routine {

namespace other {

SelectSeed::SelectSeed(struct IJONState &state) : state(state) {}

/**
 * Corresponding code of original IJON implementation:
 * https://github.com/RUB-SysSec/ijon/blob/4cb8ae04d/afl-fuzz.c#L4977-L5002
 */
utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
SelectSeed::operator()(void) {
  // Although IJON itself doesn't use current_entry, ShowState requires the
  // value is pointing a valid seed. So if current_entry is at the end of seeds,
  // it must be modified temporary.
  if (state.current_entry >= state.case_queue.size()) {
    if (!state.current_entry_is_swapped) {
      state.current_entry_is_swapped = true;
      state.old_current_entry = state.current_entry;
    }
    state.current_entry = 0u;
  }

  utils::StdoutLogger::Println("scheduled max input!!!!");

  u32 idx = afl::util::UR(state.nonempty_inputs.size(), state.rand_fd);
  auto &selected_input = *state.nonempty_inputs[idx];
  utils::StdoutLogger::Println("schedule: " +
                               selected_input.GetPath().string());

  state.orig_perf = 100;

  // Unlike AFL, selected_input is never modified.
  // So we can immediately load it with mmap.
  selected_input.LoadByMmap();

  auto mutator = IJONMutator(selected_input, state);
  CallSuccessors(mutator);

  selected_input.Unload();

  return GoToDefaultNext();
}

PrintAflIsSelected::PrintAflIsSelected() {}

/**
 * Corresponding code of original IJON implementation:
 * https://github.com/RUB-SysSec/ijon/blob/4cb8ae04d/afl-fuzz.c#L5035
 */
IJONMidCalleeRef PrintAflIsSelected::operator()(std::shared_ptr<IJONTestcase>) {
  utils::StdoutLogger::Println("scheduled normal input!!!!");
  return GoToDefaultNext();
}

}  // namespace other

namespace mutation {

using HavocBase = afl::routine::mutation::HavocBaseTemplate<IJONState>;
using IJONMutCaleeRef = afl::routine::mutation::AFLMutCalleeRef<IJONState>;

MaxHavoc::MaxHavoc(IJONState &state) : HavocBase(state) {}

/**
 * Corresponding code of original IJON implementation:
 * https://github.com/RUB-SysSec/ijon/blob/4cb8ae04d/afl-fuzz.c#L6128-L6555
 */
IJONMutCalleeRef MaxHavoc::operator()(IJONMutator &mutator) {
  if (DoHavoc(mutator, *state.havoc_optimizer, havoc::IJONCustomCases,
              "ijon-max", "ijon-max", state.orig_perf,
              afl::option::GetHavocCycles(state), afl::option::STAGE_HAVOC)) {
    SetResponseValue(true);
    return GoToParent();
  }

  return GoToDefaultNext();
}

}  // namespace mutation

namespace update {

using IJONUpdCalleeRef = afl::routine::update::AFLUpdCalleeRef;

IJONUpdate::IJONUpdate(IJONState &state, std::size_t offset_)
    : state(state), offset(offset_) {}

static void StoreMaxInput(IJONState &state, u32 idx, const u8 *data, u32 len) {
  // NOTE: is it no problem to overwrite/unload `all_inputs[idx]`,
  // even though this input can be still loaded in IJON's flow?
  // The answer is yes because Mutator copies inputs to its own buffer,
  // which means modifying these inputs doesn't affect Mutator.
  // If Mutator's implementation is changed, then we have to
  // add to ExecInput a member function that checks loaded or unloaded,
  // and use OverwriteThenUnload and OverwriteKeepingLoaded accordingly.
  state.all_inputs[idx]->OverwriteThenUnload(data, len);

  fs::path copy_fn =
      state.max_dir / fuzzuf::utils::StrPrintf("finding_%lu_%lu",
                                               state.num_updates, time(NULL));

  state.all_inputs[idx]->Copy(copy_fn);
  state.num_updates++;
}

/**
 * Corresponding code of original IJON implementation:
 * https://github.com/RUB-SysSec/ijon/blob/4cb8ae04d/afl-ijon-min.c#L68-L83
 */
IJONUpdCalleeRef IJONUpdate::operator()(
    const u8 *buf, u32 len, feedback::InplaceMemoryFeedback &inp_feed,
    feedback::ExitStatusFeedback &exit_status) {
  // Originally, this procedure is done in save_if_interesting.
  // And the update occurs only if the following condition is not met.
  if (exit_status.exit_reason != state.crash_mode) return GoToDefaultNext();

  bool should_minify = len > 512;

  auto lambda = [this, &should_minify, buf, len](const u8 *trace_bits,
                                                 u32 /*unused*/) {
    const std::uint64_t *afl_max =
        reinterpret_cast<const std::uint64_t *>(std::next(trace_bits, offset));
    for (u32 i = 0; i < option::GetMaxMapSize<option::IJONTag>(); i++) {
      bool need_update = false;

      if (afl_max[i] > state.max_map[i]) {
        need_update = true;

        if (state.max_map[i] == 0) {
          // This i-th input will be nonempty shortly,
          // so let's push it to nonempty_inputs.
          state.nonempty_inputs.emplace_back(state.all_inputs[i]);
        }

        state.max_map[i] = afl_max[i];
        utils::StdoutLogger::Println(fuzzuf::utils::StrPrintf(
            "updated maxmap %d: %lx (len: %ld)", i, state.max_map[i], len));
      } else if (should_minify && afl_max[i] == state.max_map[i] &&
                 len < state.all_inputs[i]->GetLen()) {
        need_update = true;
        utils::StdoutLogger::Println(fuzzuf::utils::StrPrintf(
            "minimized maxmap %d: %lx (len: %ld)", i, state.max_map[i], len));
      }

      if (need_update) StoreMaxInput(state, i, buf, len);
    }
  };

  inp_feed.ShowMemoryToFunc(lambda);
  return GoToDefaultNext();
}

}  // namespace update

}  // namespace fuzzuf::algorithm::ijon::routine
