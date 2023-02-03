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
#ifndef FUZZUF_INCLUDE_ALGORITHM_AFLPLUSPLUS_AFLPLUSPLUS_HAVOC_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFLPLUSPLUS_AFLPLUSPLUS_HAVOC_HPP

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/optimizer/optimizer.hpp"

namespace fuzzuf::algorithm::aflplusplus::havoc {

enum AFLplusplusExtraHavocCase : u32 {
  AFLPLUSPLUS_ADDBYTE = mutator::NUM_CASE,
  AFLPLUSPLUS_SUBBYTE,
  AFLPLUSPLUS_SWITCH_BYTES,
  AFLPLUSPLUS_SPLICE_OVERWRITE,
  AFLPLUSPLUS_SPLICE_INSERT,
  AFLPLUSPLUS_NUM_CASE  // number of cases in AFL++ havoc
};

class AFLplusplusHavocCaseDistrib : public optimizer::Optimizer<u32> {
 public:
  AFLplusplusHavocCaseDistrib();
  ~AFLplusplusHavocCaseDistrib();
  u32 CalcValue() override;
};

u32 ChooseBlockLen(u32 limit);

/*
 *  The lifetime of this struct should be shorter than State.
 */
template <class State>
struct AFLplusplusCustomCases {
  AFLplusplusCustomCases(State& _state) : state(_state) {}
  ~AFLplusplusCustomCases() {}

  void operator()(u32 case_idx, u8*& outbuf, u32& len,
                  const std::vector<afl::dictionary::AFLDictData>& extras,
                  const std::vector<afl::dictionary::AFLDictData>& a_extras);

  State& state;
};

template <class State>
void AFLplusplusCustomCases<State>::operator()(
    u32 case_idx, u8*& outbuf, u32& len,
    [[maybe_unused]] const std::vector<afl::dictionary::AFLDictData>& extras,
    [[maybe_unused]] const std::vector<afl::dictionary::AFLDictData>&
        a_extras) {
  auto UR = [](u32 limit) { return afl::util::UR(limit, -1); };

  switch (case_idx) {
    case AFLPLUSPLUS_ADDBYTE:
      outbuf[UR(len)]++;
      break;

    case AFLPLUSPLUS_SUBBYTE:
      outbuf[UR(len)]--;
      break;

    case AFLPLUSPLUS_SWITCH_BYTES: {
      if (len < 4) {
        break;
      }

      u32 to_end, switch_to, switch_len, switch_from;
      switch_from = UR(len);
      do {
        switch_to = UR(len);
      } while (switch_from == switch_to);

      if (switch_from < switch_to) {
        switch_len = switch_to - switch_from;
        to_end = len - switch_to;
      } else {
        switch_len = switch_from - switch_to;
        to_end = len - switch_from;
      }

      switch_len = ChooseBlockLen(std::min(switch_len, to_end));

      std::unique_ptr<u8[]> new_buf(new u8[switch_len]);

      /* Backup */
      memcpy(new_buf.get(), outbuf + switch_from, switch_len);

      /* Switch 1 */
      memcpy(outbuf + switch_from, outbuf + switch_to, switch_len);

      /* Switch 2 */
      memcpy(outbuf + switch_to, new_buf.get(), switch_len);

      break;
    }

    case AFLPLUSPLUS_SPLICE_OVERWRITE:
    case AFLPLUSPLUS_SPLICE_INSERT: {
      if (state.case_queue.size() <= 1) break;

      u32 tid;
      do {
        tid = UR(state.queued_paths);
      } while (tid == state.current_entry);

      if (tid == state.case_queue.size()) break;

      auto& target_case = *state.case_queue[tid];
      target_case.input->Load();

      u32 target_len = target_case.input->GetLen();

      using afl::option::GetHavocBlkXl;
      using afl::option::GetMaxFile;
      using Tag = typename State::Tag;

      if (case_idx == AFLPLUSPLUS_SPLICE_OVERWRITE ||
          len + GetHavocBlkXl<Tag>() >= GetMaxFile<Tag>()) {
        u32 copy_len = ChooseBlockLen(target_len);
        if (copy_len > len) copy_len = len;

        u32 copy_from = UR(target_len - copy_len + 1);
        u32 copy_to = UR(len - copy_len + 1);

        memmove(outbuf + copy_to, target_case.input->GetBuf() + copy_from,
                copy_len);
      } else {
        u32 clone_len = ChooseBlockLen(target_len);
        u32 clone_from = UR(target_len - clone_len + 1);
        u32 clone_to = UR(len + 1);

        u8* new_buf = new u8[len + clone_len];

        /* Head */
        std::memcpy(new_buf, outbuf, clone_to);

        /* Inserted part */
        std::memcpy(new_buf + clone_to,
                    target_case.input->GetBuf() + clone_from, clone_len);

        /* Tail */
        std::memcpy(new_buf + clone_to + clone_len, outbuf + clone_to,
                    len - clone_to);

        delete[] outbuf;
        outbuf = new_buf;
        len += clone_len;
      }

      target_case.input->Unload();

      break;
    }

    default:
      break;
  }
}

}  // namespace fuzzuf::algorithm::aflplusplus::havoc

#endif
