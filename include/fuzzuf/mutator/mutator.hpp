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

#ifndef FUZZUF_INCLUDE_MUTATOR_MUTATOR_HPP
#define FUZZUF_INCLUDE_MUTATOR_MUTATOR_HPP

#include <cassert>
#include <random>
#include <variant>

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/optimizer/keys.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::mutator {

// Responsibility:
//  - An instance generates fuzzes an arbitrary number of times according to the
//  specified algorithm
//      - "The specified algorithm" includes not only primitive units provided
//      by this class's member functions, but also calls that combined them
//      - Conversely, it guarantees that multiple fuzzes will not be generated
//      from multiple seeds in a single Mutator instance
//      - It is to prevent side effects of an instance from spreading over fuzz
//      generations using other seeds
//  - The lifetime of an instance is from an instance generation with a given
//  seed to the end of the last fuzz generation
//  - A fuzz is temporarily saved to a member variable `outbuf`, and given to
//  variables depending on it through `GetBuf()` method

template <class Tag>
class Mutator {
 protected:
  // NOTE: The lifetime of Mutator must be shorter than ExecInput as it holds
  // const reference
  const fuzzuf::exec_input::ExecInput &input;

  u32 len;
  u8 *outbuf;
  u8 *tmpbuf;
  u32 temp_len;
  u8 *splbuf;
  u32 spl_len;

  std::mt19937 mt_engine;  // TODO: Enabling Dependency Injection for an
                           // easiness of tests
  int rand_fd;

 public:
  static const std::vector<s8> interesting_8;
  static const std::vector<s16> interesting_16;
  static const std::vector<s32> interesting_32;

  // Forbid copy constructors
  // Avoid implicit copies when we write `return std::move(mutator)` as `return
  // mutator` to prevent compile errors
  Mutator(const Mutator &) = delete;
  Mutator(Mutator &) = delete;

  // ムーブコンストラクタ
  Mutator(Mutator &&);

  Mutator(const fuzzuf::exec_input::ExecInput &);
  virtual ~Mutator();

  u8 *GetBuf() { return outbuf; }
  u32 GetLen() { return len; }
  virtual u32 ChooseBlockLen(u32);
  u32 OverwriteWithSet(u32 pos, const std::vector<char> &char_set);
  u32 FlipBit(u32 pos, int n);
  u32 FlipByte(u32, int);

  void Replace(int pos, const u8 *buf, u32 len);
  void Insert(u32 pos, const u8 *buf, u32 extra_len);
  void Delete(u32 pos, u32 n);

  template <typename T>
  T ReadMem(u32 pos);
  template <typename T>
  u32 Overwrite(u32 pos, T chr);

  template <typename T>
  u32 AddN(int pos, int val, int be);
  template <typename T>
  u32 SubN(int pos, int val, int be);
  template <typename T>
  u32 InterestN(int pos, int idx, int be);

  using AFLDictData = fuzzuf::algorithm::afl::dictionary::AFLDictData;
  /**
   * @fn Havoc
   * @tparam CustomCases the type of the function that represents custom cases
   * in havoc. It should be `void(u32, u8*&, u32&, const
   * std::vector<AFLDictData>&, const std::vector<AFLDictData>&)`.
   * @param extras the vector of extras (constant strings) that works as a
   * dictionary.
   * @param a_extras the vector of auto extras (automatically generated constant
   * strings).
   * @param havoc_optimizer (the reference of) the optimizer that selects
   * mutation operators to be applied and the number of times mutation operators
   * are applied.
   * @note About havoc_optimizer and CustomCases.
   * To allow users to customize Havoc, two callable objects are provided.
   *
   * havoc_optimizer should be an instance of
   * `fuzzuf::optimizer::HavocOptimizer`. `HavocOptimizer::CalcMutop` should
   * return integers that describe switch cases of havoc (i.e., a constant
   * defined in HavocCase).
   * This works as a probability distribution with which Havoc decides which
   * mutation (switch case) to be used. `CalcMutop` is provided with two
   * dictionaries via `fuzzuf::optimizer::Store`: extras and a_extras. They can
   * be accessed with the keys `optimizer::keys::Extras` and
   * `optimizer::keys::AutoExtras`. If these dictionaries are available and
   * non-empty, `CalcMutop` can select the mutation operators of placing
   * keywords picked from the dictionaries. Note that, conversely,
   * `CalcMutop` MUST NOT return OVERWRITE_WITH_EXTRA and INSERT_EXTRA if
   * the value extras is empty. If it does, Havoc can cause access violations.
   * The same is true for OVERWRITE_WITH_AEXTRA and INSERT_AEXTRA.
   * `HavocOptimizer::CalcBatchSize` should return how many times mutation
   * operators should be applied to the retained buffer.
   *
   * CustomCases is a callable object used to execute your own cases instead of
   * preset cases. It should receive as its arguments a number representing
   * which case should be executed, the references of outbuf and len, extras and
   * a_extras. Note that, in order to select custom cases in Havoc, CaseDistrib
   * should return numbers more than or equal to HavocCase::NUM_CASE. For
   * example, if CaseDistrib returns HavocCase::NUM_CASE+1, then CustomCases
   * receives HavocCase::NUM_CASE+1 as one of its arguments.
   */
  template <typename CustomCases>
  void Havoc(const std::vector<AFLDictData> &extras,
             const std::vector<AFLDictData> &a_extras,
             optimizer::HavocOptimizer &havoc_optimizer,
             CustomCases custom_cases);

  void RestoreHavoc(void);

  const fuzzuf::exec_input::ExecInput &GetSource();

  bool Splice(const fuzzuf::exec_input::ExecInput &target);
  void RestoreSplice(void);
};

/* TODO: Implement generator class */

template <class Tag>
template <typename T>
T Mutator<Tag>::ReadMem(u32 pos) {
  // Special case: we don't need to care about alignment on u8.
  if constexpr (std::is_same_v<u8, T>) {
    return outbuf[pos];
  }

  // To avoid unaligned memory access, we use memcpy
  T ret;
  std::memcpy(&ret, outbuf + pos, sizeof(T));
  return ret;
}

template <class Tag>
template <typename T>
u32 Mutator<Tag>::Overwrite(u32 pos, T chr) {
  // Special case: we don't need to care about alignment on u8.
  if constexpr (std::is_same_v<u8, T>) {
    outbuf[pos] = chr;
    return 1;
  }

  // To avoid unaligned memory access, we use memcpy
  std::memcpy(outbuf + pos, &chr, sizeof(T));
  return 1;
}

template <class Tag>
template <typename T>
u32 Mutator<Tag>::AddN(int pos, int val, int be) {
  T orig = ReadMem<T>(pos);
  T r;

  const int n = sizeof(T);
  if (n == 1) {
    r = orig + val;
  } else if (n == 2) {
    if (be)
      r = SWAP16(SWAP16(orig) + val);
    else
      r = orig + val;
  } else if (n == 4) {
    if (be)
      r = SWAP32(SWAP32(orig) + val);
    else
      r = orig + val;
  }

  Overwrite<T>(pos, r);
  return 1;
}

template <class Tag>
template <typename T>
u32 Mutator<Tag>::SubN(int pos, int val, int be) {
  T orig = ReadMem<T>(pos);
  T r;

  const int n = sizeof(T);
  if (n == 1) {
    r = orig - val;
  } else if (n == 2) {
    if (be)
      r = SWAP16(SWAP16(orig) - val);
    else
      r = orig - val;
  } else if (n == 4) {
    if (be)
      r = SWAP32(SWAP32(orig) - val);
    else
      r = orig - val;
  }

  Overwrite<T>(pos, r);

  return 1;
}

template <class Tag>
template <typename T>
u32 Mutator<Tag>::InterestN(int pos, int idx, int be) {
  constexpr int n = sizeof(T);
  static_assert(n == 1 || n == 2 || n == 4,
                "Mutator::InterestN : T has unsupported size");

  if (n == 1) {
    Overwrite<T>(pos, interesting_8[idx]);
  }
  if (n == 2) {
    if (be)
      Overwrite<T>(pos, SWAP16(interesting_16[idx]));
    else
      Overwrite<T>(pos, interesting_16[idx]);
  }
  if (n == 4) {
    if (be)
      Overwrite<T>(pos, SWAP32(interesting_32[idx]));
    else
      Overwrite<T>(pos, interesting_32[idx]);
  }

  return 1;
}

template <class Tag>
template <typename CustomCases>
void Mutator<Tag>::Havoc(const std::vector<AFLDictData> &extras,
                         const std::vector<AFLDictData> &a_extras,
                         optimizer::HavocOptimizer &havoc_optimizer,
                         CustomCases custom_cases) {
  using namespace fuzzuf::algorithm;
  using afl::option::GetArithMax;
  using afl::option::GetHavocBlkXl;
  using afl::option::GetMaxFile;

  // FIXME: all the operations can be rewritten with vector<u8>

  if (temp_len < len) {
    delete[] tmpbuf;
    tmpbuf = nullptr;
  }

  if (!tmpbuf) {
    tmpbuf = new u8[len];
  }

  std::memcpy(tmpbuf, outbuf, len);
  temp_len = len;

  // swap outbuf and tmpbuf to use mutation function on tmpbuf
  // also, if we want to restore the original buffer
  // we can just swap them again
  std::swap(outbuf, tmpbuf);
  std::swap(len, temp_len);

  // just an alias of afl::util::UR
  auto UR = [this](u32 limit) { return afl::util::UR(limit, rand_fd); };

  using AFLDictRef =
      utils::NullableRef<const std::vector<afl::dictionary::AFLDictData>>;
  optimizer::Store::GetInstance().Set(optimizer::keys::Extras,
                                      AFLDictRef(extras));
  optimizer::Store::GetInstance().Set(optimizer::keys::AutoExtras,
                                      AFLDictRef(a_extras));

  bool useSelectedCaseHistogram = optimizer::Store::GetInstance().Exists(
      optimizer::keys::SelectedCaseHistogram);

  bool useIsMutopBanned =
      optimizer::Store::GetInstance().Exists(optimizer::keys::IsMutopBanned);
  auto check_banned_mutops = [&extras, &a_extras](u32 len) {
    // Never prepare a new `is_mutop_banned` instance. The size of it is unknown
    // due to CustomCases.
    auto &is_mutop_banned = optimizer::Store::GetInstance().GetMutRef(
        optimizer::keys::IsMutopBanned, true);
    std::fill(is_mutop_banned.begin(), is_mutop_banned.end(), false);

    if (extras.empty()) {
      is_mutop_banned[INSERT_EXTRA] = true;
      is_mutop_banned[OVERWRITE_WITH_EXTRA] = true;
    }

    if (a_extras.empty()) {
      is_mutop_banned[INSERT_AEXTRA] = true;
      is_mutop_banned[OVERWRITE_WITH_AEXTRA] = true;
    }

    if (len + GetHavocBlkXl<Tag>() >= GetMaxFile<Tag>()) {
      is_mutop_banned[CLONE_BYTES] = true;
      is_mutop_banned[INSERT_SAME_BYTE] = true;
    } else if (len < 4) {
      is_mutop_banned[FLIP32] = true;
      is_mutop_banned[INT32_LE] = true;
      is_mutop_banned[INT32_BE] = true;
      is_mutop_banned[SUB32_LE] = true;
      is_mutop_banned[SUB32_BE] = true;
      is_mutop_banned[ADD32_LE] = true;
      is_mutop_banned[ADD32_BE] = true;
      is_mutop_banned[SUBADD32] = true;

      if (len < 2) {
        is_mutop_banned[FLIP16] = true;
        is_mutop_banned[INT16_LE] = true;
        is_mutop_banned[INT16_BE] = true;
        is_mutop_banned[SUB16_LE] = true;
        is_mutop_banned[SUB16_BE] = true;
        is_mutop_banned[ADD16_LE] = true;
        is_mutop_banned[ADD16_BE] = true;
        is_mutop_banned[SUBADD16] = true;
        is_mutop_banned[DELETE_BYTES] = true;
        is_mutop_banned[OVERWRITE_WITH_CHUNK] = true;
        is_mutop_banned[OVERWRITE_WITH_SAME_BYTE] = true;
      }
    }

    // TODO: Add CustomBan for CustomCases
  };

  optimizer::Store::GetInstance().Set(optimizer::keys::SizeOfMutatedSeed, len);

  std::array<u32, NUM_CASE> selected_case_histogram;

  if (useSelectedCaseHistogram) {
    selected_case_histogram.fill(0);
  }

  // We update is_mutop_banned before calling `UpdateAndCalcBatch()`
  // because batch size and mutation operator can be determined
  // simultaneously in the function
  if (useIsMutopBanned) {
    check_banned_mutops(len);
  }

  u32 stacking = havoc_optimizer.UpdateAndCalcBatch();
  optimizer::Store::GetInstance().Set(optimizer::keys::LastHavocStacking,
                                      stacking);

  for (u32 i = 0; i < stacking; i++) {
    u32 r = havoc_optimizer.CalcMutop(i);

    switch (r) {
      case FLIP1:
        /* Flip a single bit somewhere. Spooky! */
        FlipBit(UR(len << 3), 1);
        selected_case_histogram[r] += 1;
        break;

      case FLIP2:
        /* for MOpt */

        // NOTE: unlike the original MOpt, we removed "if (len < 2) break;" from
        // here. We also removed similar break conditions from other cases. We
        // think removing those doesn't change the behavior or performance of
        // the algorithm much because seeds are unlikely to be so short. On the
        // contrary, reserving those makes it difficult to standardize and reuse
        // each case in different algorithms. If you have a strong objection to
        // this decision with sound reasons, please let us know.

        FlipBit(UR((len << 3) - 1), 2);
        selected_case_histogram[r] += 1;
        break;

      case FLIP4:
        /* for MOpt */
        FlipBit(UR((len << 3) - 3), 4);
        selected_case_histogram[r] += 1;
        break;

      case FLIP8:
        /* for MOpt */
        FlipByte(UR(len), 1);
        selected_case_histogram[r] += 1;
        break;

      case FLIP16:
        /* for MOpt */

        if (len < 2) break;

        FlipByte(UR(len - 1), 2);
        selected_case_histogram[r] += 1;
        break;

      case FLIP32:
        /* for MOpt */

        if (len < 4) break;

        FlipByte(UR(len - 3), 4);
        selected_case_histogram[r] += 1;
        break;

      case INT8:
        /* Set byte to interesting value. */
        InterestN<u8>(UR(len), UR(interesting_8.size()), false);
        selected_case_histogram[r] += 1;
        break;

      case INT16_LE:
        [[fallthrough]];
      case INT16_BE:
        /* Set word to interesting value, little endian. */
        /* Set word to interesting value, big endian. */

        if (len < 2) break;

        InterestN<u16>(UR(len - 1), UR(interesting_16.size()), r == INT16_BE);
        selected_case_histogram[r] += 1;
        break;

      case INT32_LE:
        [[fallthrough]];
      case INT32_BE:
        /* Set dword to interesting value, little endian. */
        /* Set dword to interesting value, big endian. */

        if (len < 4) break;

        InterestN<u32>(UR(len - 3), UR(interesting_32.size()), r == INT32_BE);
        selected_case_histogram[r] += 1;
        break;

      case SUB8:
        /* Randomly subtract from byte. */
        SubN<u8>(UR(len), 1 + UR(GetArithMax<Tag>()), false);
        selected_case_histogram[r] += 1;
        break;

      case ADD8:
        /* Randomly add to byte. */
        AddN<u8>(UR(len), 1 + UR(GetArithMax<Tag>()), false);
        selected_case_histogram[r] += 1;
        break;

      case SUB16_LE:
        [[fallthrough]];
      case SUB16_BE:
        /* Randomly subtract from word, little endian. */
        /* Randomly subtract from word, big endian. */

        if (len < 2) break;

        SubN<u16>(UR(len - 1), 1 + UR(GetArithMax<Tag>()), r == SUB16_BE);
        selected_case_histogram[r] += 1;
        break;

      case ADD16_LE:
        [[fallthrough]];
      case ADD16_BE:
        /* Randomly add to word, little endian. */
        /* Randomly add to word, big endian. */

        if (len < 2) break;

        AddN<u16>(UR(len - 1), 1 + UR(GetArithMax<Tag>()), r == ADD16_BE);
        selected_case_histogram[r] += 1;
        break;

      case SUB32_LE:
        [[fallthrough]];
      case SUB32_BE:
        /* Randomly subtract from dword, little endian. */
        /* Randomly subtract from dword, big endian. */

        if (len < 4) break;

        SubN<u32>(UR(len - 3), 1 + UR(GetArithMax<Tag>()), r == SUB32_BE);
        selected_case_histogram[r] += 1;
        break;

      case ADD32_LE:
        [[fallthrough]];
      case ADD32_BE:
        /* Randomly add to dword, little endian. */
        /* Randomly add to dword, big endian. */

        if (len < 4) break;

        AddN<u32>(UR(len - 3), 1 + UR(GetArithMax<Tag>()), r == ADD32_BE);
        selected_case_histogram[r] += 1;
        break;

      case SUBADD8:
        /* for MOpt */

        SubN<u8>(UR(len), 1 + UR(GetArithMax<Tag>()), false);
        AddN<u8>(UR(len), 1 + UR(GetArithMax<Tag>()), false);
        selected_case_histogram[r] += 1;
        break;

      case SUBADD16:
        /* for MOpt */

        // NOTE: we think no algorithm wants to use SUBADD, except MOpt.
        // Therefore, unlike ADD32_LE & ADD32_BE, we use just SUBADD16
        // instead of prepareing 4 cases like SUBADD16_LELE, SUBADD16_LEGE, ...

        if (len < 2) break;

        /* Randomly subtract from word, random endian. */
        SubN<u16>(UR(len - 1), 1 + UR(GetArithMax<Tag>()), UR(2));

        /* Randomly add to word, random endian. */
        AddN<u16>(UR(len - 1), 1 + UR(GetArithMax<Tag>()), UR(2));

        selected_case_histogram[r] += 1;
        break;

      case SUBADD32:
        /* for MOpt */

        if (len < 4) break;

        /* Randomly subtract from dword, random endian. */
        SubN<u32>(UR(len - 3), 1 + UR(GetArithMax<Tag>()), UR(2));

        /* Randomly add to dword, random endian. */
        AddN<u32>(UR(len - 3), 1 + UR(GetArithMax<Tag>()), UR(2));

        selected_case_histogram[r] += 1;
        break;

      case XOR:
        /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */
        outbuf[UR(len)] ^= 1 + UR(255);
        selected_case_histogram[r] += 1;
        break;

      case DELETE_BYTES: {
        /* Delete bytes. We're making this a bit more likely
           than insertion (the next option) in hopes of keeping
           files reasonably small. */

        if (len < 2) break;

        /* Don't delete too much. */
        u32 del_len = ChooseBlockLen(len - 1);
        u32 del_from = UR(len - del_len + 1);

        std::memmove(outbuf + del_from, outbuf + del_from + del_len,
                     len - del_from - del_len);
        len -= del_len;

        selected_case_histogram[r] += 1;
        break;
      }

      case CLONE_BYTES:
        if (len + GetHavocBlkXl<Tag>() < GetMaxFile<Tag>()) {
          /* Clone bytes. */

          u32 clone_len = ChooseBlockLen(len);
          u32 clone_from = UR(len - clone_len + 1);
          u32 clone_to = UR(len);

          u8 *new_buf = new u8[len + clone_len];

          /* Head */
          std::memcpy(new_buf, outbuf, clone_to);

          /* Inserted part */
          std::memcpy(new_buf + clone_to, outbuf + clone_from, clone_len);

          /* Tail */
          std::memcpy(new_buf + clone_to + clone_len, outbuf + clone_to,
                      len - clone_to);
          delete[] outbuf;
          outbuf = new_buf;
          len += clone_len;
          selected_case_histogram[r] += 1;
        }
        break;

      case INSERT_SAME_BYTE:
        if (len + GetHavocBlkXl<Tag>() < GetMaxFile<Tag>()) {
          /* Insert a block of constant bytes. */

          u32 clone_len = ChooseBlockLen(GetHavocBlkXl<Tag>());
          u32 clone_to = UR(len);

          u8 *new_buf = new u8[len + clone_len];

          /* Head */
          std::memcpy(new_buf, outbuf, clone_to);

          /* Inserted part */
          // FIXME: why not unroll UR(2) also and create a new case?
          std::memset(new_buf + clone_to, UR(2) ? UR(256) : outbuf[UR(len)],
                      clone_len);

          /* Tail */
          std::memcpy(new_buf + clone_to + clone_len, outbuf + clone_to,
                      len - clone_to);
          delete[] outbuf;
          outbuf = new_buf;
          len += clone_len;
          selected_case_histogram[r] += 1;
        }
        break;

      case OVERWRITE_WITH_CHUNK: {
        /* Overwrite bytes with a randomly selected chunk. */

        if (len < 2) break;

        u32 copy_len = ChooseBlockLen(len - 1);
        u32 copy_from = UR(len - copy_len + 1);
        u32 copy_to = UR(len - copy_len + 1);

        if (likely(copy_from != copy_to))
          std::memmove(outbuf + copy_to, outbuf + copy_from, copy_len);

        selected_case_histogram[r] += 1;
        break;
      }

      case OVERWRITE_WITH_SAME_BYTE: {
        /* Overwrite bytes with fixed bytes. */

        if (len < 2) break;

        u32 copy_len = ChooseBlockLen(len - 1);
        u32 copy_to = UR(len - copy_len + 1);

        // FIXME: why not unroll "UR(2)" also and create a new case?
        std::memset(outbuf + copy_to, UR(2) ? UR(256) : outbuf[UR(len)],
                    copy_len);
        selected_case_histogram[r] += 1;
        break;
      }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */

      case OVERWRITE_WITH_EXTRA:
        [[fallthrough]];
      case OVERWRITE_WITH_AEXTRA: {
        /* Overwrite bytes with an extra. */

        bool use_auto = r == OVERWRITE_WITH_AEXTRA;

        // CaseDistrib must not select these cases when there is no dictionary.
        // But this is difficult to be guaranteed, so we put asserts here.
        if (use_auto)
          DEBUG_ASSERT(!a_extras.empty());
        else
          DEBUG_ASSERT(!extras.empty());

        u32 idx = use_auto ? UR(a_extras.size()) : UR(extras.size());
        const AFLDictData &extra = use_auto ? a_extras[idx] : extras[idx];

        u32 extra_len = extra.data.size();
        if (extra_len > len) break;

        u32 insert_at = UR(len - extra_len + 1);
        std::memcpy(outbuf + insert_at, &extra.data[0], extra_len);

        selected_case_histogram[r] += 1;
        break;
      }

      case INSERT_EXTRA:
        [[fallthrough]];
      case INSERT_AEXTRA: {
        u32 insert_at = UR(len + 1);

        /* Insert an extra. Do the same dice-rolling stuff as for the
           previous case. */

        bool use_auto = r == INSERT_AEXTRA;

        // CaseDistrib must not select these cases when there is no dictionary.
        // But this is difficult to be guaranteed, so we put asserts here.
        if (use_auto)
          DEBUG_ASSERT(!a_extras.empty());
        else
          DEBUG_ASSERT(!extras.empty());

        u32 idx = use_auto ? UR(a_extras.size()) : UR(extras.size());
        const AFLDictData &extra = use_auto ? a_extras[idx] : extras[idx];

        u32 extra_len = extra.data.size();
        if (len + extra_len >= GetMaxFile<Tag>()) break;

        u8 *new_buf = new u8[len + extra_len];

        /* Head */
        std::memcpy(new_buf, outbuf, insert_at);

        /* Inserted part */
        std::memcpy(new_buf + insert_at, &extra.data[0], extra_len);

        /* Tail */
        std::memcpy(new_buf + insert_at + extra_len, outbuf + insert_at,
                    len - insert_at);

        delete[] outbuf;
        outbuf = new_buf;
        len += extra_len;

        selected_case_histogram[r] += 1;
        break;
      }

      default:
        custom_cases(r, outbuf, len, extras, a_extras);
        break;
    }

    optimizer::Store::GetInstance().Set(optimizer::keys::SizeOfMutatedSeed,
                                        len);

    if (useSelectedCaseHistogram) {
      optimizer::Store::GetInstance().Set(
          optimizer::keys::SelectedCaseHistogram, selected_case_histogram);
    }

    if (useIsMutopBanned) check_banned_mutops(len);
  }
}

}  // namespace fuzzuf::mutator

#include "fuzzuf/mutator/templates/mutator.hpp"

#endif
