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

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

#define INTERESTING_8                                    \
  -128,    /* Overflow signed 8-bit when decremented  */ \
      -1,  /*                                         */ \
      0,   /*                                         */ \
      1,   /*                                         */ \
      16,  /* One-off with common buffer size         */ \
      32,  /* One-off with common buffer size         */ \
      64,  /* One-off with common buffer size         */ \
      100, /* One-off with common buffer size         */ \
      127  /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16                                    \
  -32768,   /* Overflow signed 16-bit when decremented */ \
      -129, /* Overflow signed 8-bit                   */ \
      128,  /* Overflow signed 8-bit                   */ \
      255,  /* Overflow unsig 8-bit when incremented   */ \
      256,  /* Overflow unsig 8-bit                    */ \
      512,  /* One-off with common buffer size         */ \
      1000, /* One-off with common buffer size         */ \
      1024, /* One-off with common buffer size         */ \
      4096, /* One-off with common buffer size         */ \
      32767 /* Overflow signed 16-bit when incremented */

#define INTERESTING_32                                          \
  -2147483648LL,  /* Overflow signed 32-bit when decremented */ \
      -100663046, /* Large negative number (endian-agnostic) */ \
      -32769,     /* Overflow signed 16-bit                  */ \
      32768,      /* Overflow signed 16-bit                  */ \
      65535,      /* Overflow unsig 16-bit when incremented  */ \
      65536,      /* Overflow unsig 16 bit                   */ \
      100663045,  /* Large positive number (endian-agnostic) */ \
      2147483647  /* Overflow signed 32-bit when incremented */

namespace fuzzuf::mutator {

// FIXME: having these vectors as member variables brings
// duplication and waste since these are defined for each Tag.
template <class Tag>
const std::vector<s8> Mutator<Tag>::interesting_8{INTERESTING_8};
template <class Tag>
const std::vector<s16> Mutator<Tag>::interesting_16{INTERESTING_8,
                                                    INTERESTING_16};
template <class Tag>
const std::vector<s32> Mutator<Tag>::interesting_32{
    INTERESTING_8, INTERESTING_16, INTERESTING_32};

#undef INTERESTING_8
#undef INTERESTING_16
#undef INTERESTING_32

/* TODO: Implement generator class */
#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
    u8* _arf = (u8*)(_ar);                  \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
  } while (0)

template <class Tag>
Mutator<Tag>::Mutator(const fuzzuf::exec_input::ExecInput& input)
    : input(input),
      len(input.GetLen()),
      outbuf(new u8[len]),
      tmpbuf(nullptr),
      temp_len(0),
      splbuf(nullptr),
      spl_len(0),
      rand_fd(fuzzuf::utils::OpenFile("/dev/urandom", O_RDONLY | O_CLOEXEC)) {
  std::memcpy(outbuf, input.GetBuf(), len);
}

template <class Tag>
Mutator<Tag>::~Mutator() {
  if (outbuf) delete[] outbuf;
  if (tmpbuf) delete[] tmpbuf;
  if (splbuf) delete[] splbuf;
  if (rand_fd != -1) {
    fuzzuf::utils::CloseFile(rand_fd);
    rand_fd = -1;
  }
}

template <class Tag>
Mutator<Tag>::Mutator(Mutator&& src)
    : input(src.input),
      len(src.len),
      outbuf(src.outbuf),
      tmpbuf(src.tmpbuf),
      temp_len(src.temp_len),
      splbuf(src.splbuf),
      spl_len(src.spl_len),
      rand_fd(src.rand_fd) {
  src.outbuf = nullptr;
  src.tmpbuf = nullptr;
  src.splbuf = nullptr;
  src.rand_fd = -1;
}

template <class Tag>
const fuzzuf::exec_input::ExecInput& Mutator<Tag>::GetSource() {
  return input;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

template <class Tag>
u32 Mutator<Tag>::ChooseBlockLen(u32 limit) {
  using namespace fuzzuf::algorithm;

  u32 min_value, max_value;
  u32 rlim = 3ULL;

  // just an alias of afl::util::UR
  auto UR = [this](u32 limit) { return afl::util::UR(limit, rand_fd); };

  switch (UR(rlim)) {
    case 0:
      min_value = 1;
      max_value = afl::option::GetHavocBlkSmall<Tag>();
      break;

    case 1:
      min_value = afl::option::GetHavocBlkSmall<Tag>();
      max_value = afl::option::GetHavocBlkMedium<Tag>();
      break;
    default:
      if (UR(10)) {
        min_value = afl::option::GetHavocBlkMedium<Tag>();
        max_value = afl::option::GetHavocBlkLarge<Tag>();
      } else {
        min_value = afl::option::GetHavocBlkLarge<Tag>();
        max_value = afl::option::GetHavocBlkXl<Tag>();
      }
  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(std::min(max_value, limit) - min_value + 1);
}

// FIXME: Suspected buffer overruns for all mutation algorithms below, fix
// required The responsibility for value checks should lie with Mutator class
// because it knows internal logics. Use DEBUG_ASSERT() if the implementation
// matters the performance.

template <class Tag>
u32 Mutator<Tag>::OverwriteWithSet(u32 pos, const std::vector<char>& char_set) {
  std::vector<char> out;
  std::sample(char_set.begin(), char_set.end(), std::back_inserter(out), 1,
              mt_engine);
  outbuf[pos] = out[0];
  return 1;
}

template <class Tag>
u32 Mutator<Tag>::FlipBit(u32 pos, int n) {
  /* Flip bits */

  for (int i = 0; i < n;
       i++) {  // Suspected buffer overrun when pos + n - 1 > sizeof(outbuf)?
    u32 flip = pos + i;
    FLIP_BIT(outbuf, flip);
  }

  return 1;
}

template <class Tag>
u32 Mutator<Tag>::FlipByte(u32 pos, int n) {
  /* Flip bytes */

  // why we don't *(T*)(outbuf + pos) ^= T(1 << n) - 1; ?
  // it can be unaligned memory access
  if (n == 1) {
    outbuf[pos] ^= 0xff;
  } else if (n == 2) {
    u16 v = ReadMem<u16>(pos);
    Overwrite<u16>(pos, (v ^ 0xFFFF));
  } else if (n == 4) {
    u32 v = ReadMem<u32>(pos);
    Overwrite<u32>(pos, (v ^ 0xFFFFFFFF));
  }

  return 1;
}

template <class Tag>
void Mutator<Tag>::Replace(int pos, const u8* buf, u32 len) {
  std::memcpy(outbuf + pos, buf, len);
}

template <class Tag>
void Mutator<Tag>::Insert(u32 pos, const u8* buf, u32 extra_len) {
  u8* new_buf = new u8[len + extra_len];

  /* Head */
  std::memcpy(new_buf, outbuf, pos);

  /* Inserted part */
  std::memcpy(new_buf + pos, buf, extra_len);

  /* Tail */
  std::memcpy(new_buf + pos + extra_len, outbuf + pos, len - pos);

  delete[] outbuf;
  outbuf = new_buf;
  len += extra_len;
}

template <class Tag>
void Mutator<Tag>::Delete(u32 pos, u32 n) {
  std::memmove(outbuf + pos, outbuf + pos + n, len - pos - n);
  len -= n;
}

// FIXME: add a test which uses this with AFLMutationHierarFlowRoutines
template <class Tag>
void Mutator<Tag>::RestoreHavoc(void) {
  std::swap(outbuf, tmpbuf);
  std::swap(len, temp_len);
}

// return true if the splice occurred, and false otherwise
template <class Tag>
bool Mutator<Tag>::Splice(const fuzzuf::exec_input::ExecInput& target) {
  auto cmp_len = std::min(len, target.GetLen());
  auto [f_diff, l_diff] =
      fuzzuf::utils::LocateDiffs(outbuf, target.GetBuf(), cmp_len);

  if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) return false;

  /* Split somewhere between the first and last differing byte. */

  using fuzzuf::algorithm::afl::util::UR;
  u32 split_at = f_diff + UR(l_diff - f_diff, rand_fd);

  /* Do the thing. */

  if (!splbuf) {
    splbuf = new u8[target.GetLen()];
  } else if (spl_len < target.GetLen()) {
    // We reallocate a buffer only when its size is not enough
    delete[] splbuf;
    splbuf = new u8[target.GetLen()];
  }

  spl_len = target.GetLen();
  std::memcpy(splbuf, outbuf, split_at);
  std::memcpy(splbuf + split_at, target.GetBuf() + split_at,
              spl_len - split_at);

  std::swap(outbuf, splbuf);
  std::swap(len, spl_len);
  return true;
}

// FIXME: add a test which uses this with AFLMutationHierarFlowRoutines
template <class Tag>
void Mutator<Tag>::RestoreSplice(void) {
  std::swap(outbuf, splbuf);
  std::swap(len, spl_len);
}

}  // namespace fuzzuf::mutator

#undef FLIP_BIT
