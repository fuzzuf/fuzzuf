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

#include <cassert>
#include <random>

#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl {

/* TODO: Implement generator class */

template <class State>
AFLMutatorTemplate<State>::AFLMutatorTemplate(
    const exec_input::ExecInput& input, const State& state)
    : fuzzuf::mutator::Mutator<typename State::Tag>(input), state(state) {}

template <class State>
AFLMutatorTemplate<State>::~AFLMutatorTemplate() {}

template <class State>
AFLMutatorTemplate<State>::AFLMutatorTemplate(AFLMutatorTemplate&& src)
    : fuzzuf::mutator::Mutator<typename State::Tag>(std::move(src)),
      state(src.state) {}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

template <class State>
u32 AFLMutatorTemplate<State>::ChooseBlockLen(u32 limit) {
  u32 min_value, max_value;
  u32 rlim = std::min(state.queue_cycle, 3ULL);

  if (!state.run_over10m) rlim = 1;

  // just an alias of afl::util::UR
  auto UR = [this](u32 limit) { return afl::util::UR(limit, state.rand_fd); };

  switch (UR(rlim)) {
    case 0:
      min_value = 1;
      max_value = option::GetHavocBlkSmall<Tag>();
      break;

    case 1:
      min_value = option::GetHavocBlkSmall<Tag>();
      max_value = option::GetHavocBlkMedium<Tag>();
      break;
    default:
      if (UR(10)) {
        min_value = option::GetHavocBlkMedium<Tag>();
        max_value = option::GetHavocBlkLarge<Tag>();
      } else {
        min_value = option::GetHavocBlkLarge<Tag>();
        max_value = option::GetHavocBlkXl<Tag>();
      }
  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(std::min(max_value, limit) - min_value + 1);
}

// FIXME: these three functions easily get buggy and
// difficult to check with eyes. We should add tests.

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

template <class State>
bool AFLMutatorTemplate<State>::CouldBeBitflip(u32 val) {
  u32 sh = 0;
  if (!val) return true;
  /* Shift left until first bit set. */
  while (!(val & 1)) {
    sh++;
    val >>= 1;
  }
  /* 1-, 2-, and 4-bit patterns are OK anywhere. */
  if (val == 1 || val == 3 || val == 15) return true;
  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
      divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return false;

  if (val == 0xff || val == 0xffff || val == 0xffffffff) return true;
  return false;
}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

template <class State>
bool AFLMutatorTemplate<State>::CouldBeArith(u32 old_val, u32 new_val,
                                             u8 blen) {
  u32 i, ov = 0, nv = 0, diffs = 0;
  if (old_val == new_val) return true;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {
    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {
      diffs++;
      ov = a;
      nv = b;
    }
  }
  /* If only one byte differs and the values are within range, return 1. */
  if (diffs == 1) {
    if ((u8)(ov - nv) <= option::GetArithMax<Tag>() ||
        (u8)(nv - ov) <= option::GetArithMax<Tag>())
      return true;
  }

  if (blen == 1) return false;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {
    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);
    if (a != b) {
      diffs++;
      ov = a;
      nv = b;
    }
  }
  /* If only one word differs and the values are within range, return 1. */
  if (diffs == 1) {
    if ((u16)(ov - nv) <= option::GetArithMax<Tag>() ||
        (u16)(nv - ov) <= option::GetArithMax<Tag>())
      return true;

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= option::GetArithMax<Tag>() ||
        (u16)(nv - ov) <= option::GetArithMax<Tag>())
      return true;
  }
  /* Finally, let's do the same thing for dwords. */
  if (blen == 4) {
    if ((u32)(old_val - new_val) <= option::GetArithMax<Tag>() ||
        (u32)(new_val - old_val) <= option::GetArithMax<Tag>())
      return true;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= option::GetArithMax<Tag>() ||
        (u32)(new_val - old_val) <= option::GetArithMax<Tag>())
      return true;
  }
  return false;
}
/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

// We implicitly assume blen <= 4
template <class State>
bool AFLMutatorTemplate<State>::CouldBeInterest(u32 old_val, u32 new_val,
                                                u8 blen, u8 check_le) {
  u32 i, j;

  if (old_val == new_val) return true;

  /* See if one-byte insertions from interesting_8 over old_val could
      produce new_val. */
  for (i = 0; i < blen; i++) {
    for (j = 0; j < this->interesting_8.size(); j++) {
      // NOTE: "u32(interesting_8[j])" and "u32(u8(interesting_8[j]))"
      // are different(don't use the former).
      // For example, if interesting_8[j] == -1, they are FFFFFFFF and FF
      u8 ubyte = this->interesting_8[j];
      u32 tval = (old_val & ~u32(0xfful << (i * 8))) | (u32(ubyte) << (i * 8));

      if (new_val == tval) return true;
    }
  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
      as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return false;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1u; i++) {
    for (j = 0; j < this->interesting_16.size(); j++) {
      u16 uword = this->interesting_16[j];
      u32 tval =
          (old_val & ~u32(0xfffful << (i * 8))) | (u32(uword) << (i * 8));

      if (new_val == tval) return true;

      /* Continue here only if blen > 2. */

      if (blen > 2) {
        tval = (old_val & ~u32(0xfffful << (i * 8))) |
               (u32(SWAP16(uword)) << (i * 8));
        if (new_val == tval) return true;
      }
    }
  }

  if (blen == 4 && check_le) {
    /* See if four-byte insertions could produce the same result
       (LE only). */
    for (j = 0; j < this->interesting_32.size(); j++)
      if (new_val == (u32)this->interesting_32[j]) return true;
  }

  return false;
}

}  // namespace fuzzuf::algorithm::afl
