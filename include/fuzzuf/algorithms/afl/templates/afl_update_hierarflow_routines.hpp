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
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "fuzzuf/algorithms/afl/afl_macro.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/mutator/mutator.hpp"

namespace fuzzuf::algorithm::afl::routine::update {

template <class State>
static std::string DescribeOp(const State &state, u8 hnb) {
  std::string ret;

  if (!state.syncing_party.empty()) {
    ret = fuzzuf::utils::StrPrintf(
        "sync:%s,src:%06u", state.syncing_party.c_str(), state.syncing_case);
  } else {
    ret = fuzzuf::utils::StrPrintf("src:%06u", state.current_entry);

    if (state.splicing_with >= 0) {
      ret += fuzzuf::utils::StrPrintf("+%06u", state.splicing_with);
    }

    ret += ",op:" + state.stage_short;

    if (state.stage_cur_byte >= 0) {
      ret += fuzzuf::utils::StrPrintf(",pos:%u", state.stage_cur_byte);

      if (state.stage_val_type != option::STAGE_VAL_NONE) {
        ret += fuzzuf::utils::StrPrintf(
            ",val:%s%+d",
            (state.stage_val_type == option::STAGE_VAL_BE) ? "be:" : "",
            state.stage_cur_val);
      }
    } else {
      ret += fuzzuf::utils::StrPrintf(",rep:%u", state.stage_cur_val);
    }
  }

  if (hnb == 2) ret += ",+cov";

  return ret;
}

template <class State>
static void MaybeAddAuto(State &state, const std::vector<u8> &mem) {
  using afl::dictionary::AFLDictData;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (option::GetMaxAutoExtras(state) == 0 ||
      option::GetUseAutoExtras(state) == 0)
    return;

  /* Skip runs of identical bytes. */

  if (mem == std::vector<u8>(mem.size(), mem[0])) return;

  /* Reject builtin interesting values. */

  if (mem.size() == 2) {
    u16 converted = *(u16 *)mem.data();
    for (auto val :
         fuzzuf::mutator::Mutator<typename State::Tag>::interesting_16) {
      if (converted == (u16)val || converted == SWAP16(val)) return;
    }
  } else if (mem.size() == 4) {
    u32 converted = *(u32 *)mem.data();
    for (auto val :
         fuzzuf::mutator::Mutator<typename State::Tag>::interesting_32) {
      if (converted == (u32)val || converted == SWAP32(val)) return;
    }
  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  auto itr = state.extras.begin();
  for (; itr != state.extras.end(); itr++) {
    if (itr->data.size() >= mem.size()) break;
  }

  const auto CheckEqualNocase = [](const std::vector<u8> &m1,
                                   const std::vector<u8> &m2) -> bool {
    // NOTE: this function implicitly assumes m1.size() == m2.size()
    u32 len = m1.size();

    for (u32 i = 0; i < len; i++) {
      if (std::tolower(m1[i]) != std::tolower(m2[i])) return false;
    }

    return true;
  };

  for (; itr != state.extras.end() && itr->data.size() == mem.size(); itr++) {
    if (CheckEqualNocase(itr->data, mem)) return;
  }

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  state.auto_changed = 1;

  bool will_append = true;
  for (auto &extra : state.a_extras) {
    if (extra.data.size() == mem.size() && CheckEqualNocase(extra.data, mem)) {
      extra.hit_cnt++;
      will_append = false;
      break;
    }
  }

  if (will_append) {
    /* At this point, looks like we're dealing with a new entry. So, let's
       append it if we have room. Otherwise, let's randomly evict some other
       entry from the bottom half of the list. */

    if (state.a_extras.size() < option::GetMaxAutoExtras(state)) {
      state.a_extras.emplace_back(AFLDictData{mem, 0});
    } else {
      using afl::util::UR;

      int idx = option::GetMaxAutoExtras(state) / 2;
      idx += UR((option::GetMaxAutoExtras(state) + 1) / 2, state.rand_fd);

      state.a_extras[idx].data = mem;
      state.a_extras[idx].hit_cnt = 0;
    }
  }

  std::sort(state.a_extras.begin(), state.a_extras.end(),
            [](const AFLDictData &e1, const AFLDictData &e2) {
              return e1.hit_cnt > e2.hit_cnt;
            });

  size_t lim =
      std::min<size_t>(option::GetUseAutoExtras(state), state.a_extras.size());
  std::sort(state.a_extras.begin(), state.a_extras.begin() + lim,
            [](const AFLDictData &e1, const AFLDictData &e2) {
              return e1.data.size() < e2.data.size();
            });
}

template <class State>
NormalUpdateTemplate<State>::NormalUpdateTemplate(State &state)
    : state(state) {}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning true if it's time to bail out. */

template <class State>
AFLUpdCalleeRef NormalUpdateTemplate<State>::operator()(
    const u8 *buf, u32 len, feedback::InplaceMemoryFeedback &inp_feed,
    feedback::ExitStatusFeedback &exit_status) {
  if (state.stop_soon) {
    SetResponseValue(true);
    return GoToParent();
  }

  if (exit_status.exit_reason == feedback::PUTExitReasonType::FAULT_TMOUT) {
    if (state.subseq_tmouts++ > option::GetTmoutLimit(state)) {
      state.cur_skipped_paths++;
      SetResponseValue(true);
      return GoToParent();
    }
  } else
    state.subseq_tmouts = 0;

    // FIXME: to handle SIGUSR1, we need to reconsider how and where we
    // implement signal handlers
#if 0
    /* Users can hit us with SIGUSR1 to request the current input
       to be abandoned. */

    if (state.skip_requested) {
        state.skip_requested = false;
        state.cur_skipped_paths++;
        SetResponseValue(true);
        return GoToParent();
    }
#endif

  if (state.SaveIfInteresting(buf, len, inp_feed, exit_status)) {
    state.queued_discovered++;
  }

  if (state.stage_cur % state.stats_update_freq == 0 ||
      state.stage_cur + 1 == state.stage_max) {
    state.ShowStats();
  }

  return GoToDefaultNext();
}

template <class State>
ConstructAutoDictTemplate<State>::ConstructAutoDictTemplate(State &state)
    : state(state) {}

// Deal with dictionary construction in bitflip 1/1 stage
template <class State>
AFLUpdCalleeRef ConstructAutoDictTemplate<State>::operator()(
    const u8 *buf, u32 /* unused */, feedback::InplaceMemoryFeedback &inp_feed,
    feedback::ExitStatusFeedback & /* unused */
) {
  if (!state.ShouldConstructAutoDict()) return GoToDefaultNext();

  u32 cksum = inp_feed.CalcCksum32();

  if (state.stage_cur == state.stage_max - 1 && cksum == state.prev_cksum) {
    /* If at end of file and we are still collecting a string, grab the
       final character and force output. */

    if (state.a_len < option::GetMaxAutoExtra(state)) {
      // At this point, the content of buf is different from the original AFL,
      // because the original one does this procedure AFTER restoring buf.
      state.a_collect.emplace_back(buf[state.stage_cur >> 3] ^ 1);
    }

    // NOTE: why do we have a_len? Isn't a_collect.size() enough?
    // In the original AFL, a_len can be MAX_AUTO_EXTRA+1:
    // when AFL tries to append a character while a_len == MAX_AUTO_EXTRA,
    // it fails to do that, only to increment a_len.
    // This is considered as the problem of the original AFL,
    // but we still follow the original one to have consistency.
    state.a_len++;

    if (option::GetMinAutoExtra(state) <= state.a_len &&
        state.a_len <= option::GetMaxAutoExtra(state)) {
      MaybeAddAuto(state, state.a_collect);
    }
  } else if (cksum != state.prev_cksum) {
    /* Otherwise, if the checksum has changed, see if we have something
       worthwhile queued up, and collect that if the answer is yes. */

    if (option::GetMinAutoExtra(state) <= state.a_len &&
        state.a_len <= option::GetMaxAutoExtra(state)) {
      MaybeAddAuto(state, state.a_collect);
    }

    state.a_collect.clear();
    state.a_len = 0;
    state.prev_cksum = cksum;
  }

  /* Continue collecting string, but only if the bit flip actually made
     any difference - we don't want no-op tokens. */

  if (cksum != state.queue_cur_exec_cksum) {
    if (state.a_len < option::GetMaxAutoExtra(state)) {
      state.a_collect.emplace_back(buf[state.stage_cur >> 3] ^ 1);
    }
    state.a_len++;
  }

  return GoToDefaultNext();
}

template <class State>
ConstructEffMapTemplate<State>::ConstructEffMapTemplate(State &state)
    : state(state) {}

// Deal with eff_map construction in bitflip 8/8 stage
template <class State>
AFLUpdCalleeRef ConstructEffMapTemplate<State>::operator()(
    const u8 * /* unused */, u32 len, feedback::InplaceMemoryFeedback &inp_feed,
    feedback::ExitStatusFeedback & /* unused */
) {
  /* We also use this stage to pull off a simple trick: we identify
     bytes that seem to have no effect on the current execution path
     even when fully flipped - and we skip them during more expensive
     deterministic stages, such as arithmetics or known ints. */

  using Tag = typename State::Tag;

  using afl::util::EFF_APOS;

  if (!state.eff_map[EFF_APOS<Tag>(state.stage_cur)]) {
    bool set_eff_map_bit = false;
    if (state.setting->dumb_mode || len < option::GetEffMinLen(state)) {
      set_eff_map_bit = true;
    } else {
      u32 cksum = inp_feed.CalcCksum32();
      if (cksum != state.queue_cur_exec_cksum) {
        set_eff_map_bit = true;
      }
    }

    if (set_eff_map_bit) {
      state.eff_map[EFF_APOS<Tag>(state.stage_cur)] = 1;
      state.eff_cnt++;
    }
  }

  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::afl::routine::update
