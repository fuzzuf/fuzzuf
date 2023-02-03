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

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl {

// Inherited Mutator class with AFL's own pruning
// NOTE: AFLMutatorTemplate is not "fully" inherited from Mutator
// Mutator's member functions are not virtual.
// Hence you must not treat this as Mutator instance

template <class State>
class AFLMutatorTemplate
    : public fuzzuf::mutator::Mutator<typename State::Tag> {
 protected:
  u32 val_for_restore;
  u32 pos_for_restore;

  const State& state;

 public:
  using Tag = typename State::Tag;

  // Forbid copy constructors
  // Avoid implicit copies when we write `return std::move(mutator)` as `return
  // mutator` to prevent compile errors
  AFLMutatorTemplate(const AFLMutatorTemplate&) = delete;
  AFLMutatorTemplate(AFLMutatorTemplate&) = delete;

  // Move constructor
  AFLMutatorTemplate(AFLMutatorTemplate&&);

  AFLMutatorTemplate(const exec_input::ExecInput&, const State&);
  ~AFLMutatorTemplate();

  u32 ChooseBlockLen(u32);

  template <typename T>
  u32 AddN(int pos, int val, int be);
  template <typename T>
  u32 SubN(int pos, int val, int be);
  template <typename T>
  u32 InterestN(int pos, int idx, int be);
  template <typename T>
  void RestoreOverwrite(void);

  bool CouldBeBitflip(u32);
  bool CouldBeArith(u32, u32, u8);
  bool CouldBeInterest(u32, u32, u8, u8);
};

using AFLMutator = AFLMutatorTemplate<AFLState>;

/* TODO: Implement generator class */

// Returns if pos was actually overwritten (0 or 1)
template <class State>
template <typename T>
u32 AFLMutatorTemplate<State>::AddN(int pos, int val, int be) {
  T orig = this->template ReadMem<T>(pos);

  T r;
  bool need;

  constexpr int n = sizeof(T);

  if constexpr (n == 1) {
    if (be)
      need = false;
    else {
      need = true;
      r = orig + val;
    }
  } else if constexpr (n == 2) {
    if (be) {
      need = (orig >> 8) + val > 0xff;
      r = SWAP16(SWAP16(orig) + val);
    } else {
      need = (orig & 0xff) + val > 0xff;
      r = orig + val;
    }
  } else if constexpr (n == 4) {
    if (be) {
      need = (SWAP32(orig) & 0xffff) + val > 0xffff;
      r = SWAP32(SWAP32(orig) + val);
    } else {
      need = (orig & 0xffff) + val > 0xffff;
      r = orig + val;
    }
  }

  if (need && !CouldBeBitflip(orig ^ r)) {
    this->template Overwrite<T>(pos, r);
    val_for_restore = orig;
    pos_for_restore = pos;
    return 1;
  }

  return 0;
}

// Returns if pos was actually overwritten (0 or 1)
template <class State>
template <typename T>
u32 AFLMutatorTemplate<State>::SubN(int pos, int val, int be) {
  T orig = this->template ReadMem<T>(pos);

  T r;
  bool need;

  constexpr int n = sizeof(T);

  if constexpr (n == 1) {
    if (be)
      need = false;
    else {
      need = true;
      r = orig - val;
    }
  } else if constexpr (n == 2) {
    if (be) {
      need = int(orig >> 8) < val;
      r = SWAP16(SWAP16(orig) - val);
    } else {
      need = int(orig & 0xff) < val;
      r = orig - val;
    }
  } else if constexpr (n == 4) {
    if (be) {
      need = int(SWAP32(orig) & 0xffff) < val;
      r = SWAP32(SWAP32(orig) - val);
    } else {
      need = int(orig & 0xffff) < val;
      r = orig - val;
    }
  }

  if (need && !CouldBeBitflip(orig ^ r)) {
    this->template Overwrite<T>(pos, r);
    val_for_restore = orig;
    pos_for_restore = pos;
    return 1;
  }

  return 0;
}

// Returns if pos was actually overwritten (0 or 1)
template <class State>
template <typename T>
u32 AFLMutatorTemplate<State>::InterestN(int pos, int idx, int be) {
  T orig = this->template ReadMem<T>(pos);
  T r;

  bool need;

  constexpr int n = sizeof(T);

  if constexpr (n == 1) {
    r = (u8)this->interesting_8[idx];

    if (be)
      need = false;
    else {
      need = !CouldBeBitflip(orig ^ r) && !CouldBeArith(orig, r, 1);
    }
  } else if constexpr (n == 2) {
    if (be) {
      r = SWAP16(this->interesting_16[idx]);
      need = (u16)this->interesting_16[idx] != r;
    } else {
      r = this->interesting_16[idx];
      need = true;
    }

    need &= !CouldBeBitflip(orig ^ r);
    need &= !CouldBeArith(orig, r, 2);
    need &= !CouldBeInterest(orig, r, 2, be);
  } else if constexpr (n == 4) {
    if (be) {
      r = SWAP32(this->interesting_32[idx]);
      need = (u32)this->interesting_32[idx] != r;
    } else {
      r = this->interesting_32[idx];
      need = true;
    }

    need &= !CouldBeBitflip(orig ^ r);
    need &= !CouldBeArith(orig, r, 4);
    need &= !CouldBeInterest(orig, r, 4, be);
  }

  if (need) {
    this->template Overwrite<T>(pos, r);
    val_for_restore = orig;
    pos_for_restore = pos;
    return 1;
  }

  return 0;
}

// For restoration of AddN, SubN, InterestN
template <class State>
template <typename T>
void AFLMutatorTemplate<State>::RestoreOverwrite(void) {
  this->template Overwrite<T>(pos_for_restore, val_for_restore);
}

}  // namespace fuzzuf::algorithm::afl

#include "fuzzuf/algorithms/afl/templates/afl_mutator.hpp"
