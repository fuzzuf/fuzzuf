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
/**
 * @file VUzzerMutator.cpp
 * @brief Mutation methods of VUzzer
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/vuzzer/vuzzer_mutator.hpp"

#include <array>
#include <cassert>

#include "fuzzuf/algorithms/vuzzer/vuzzer_util.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::vuzzer {

/* FIXME: Use const/constexpr std::vector instead of */
namespace {
constexpr auto mutators_count_with_dict = 21u;
constexpr auto mutators_count_without_dict = 19u;
constexpr auto mutators =
    std::array<VUzzerMutator::MutFunc, mutators_count_with_dict>{
        &VUzzerMutator::EliminateRandom,
        &VUzzerMutator::ChangeBytes,
        &VUzzerMutator::ChangeBytes,
        &VUzzerMutator::AddRandom,
        &VUzzerMutator::AddRandom,
        &VUzzerMutator::ChangeRandom,
        &VUzzerMutator::SingleChangeRandom,
        &VUzzerMutator::LowerSingleRandom,
        &VUzzerMutator::RaiseSingleRandom,
        &VUzzerMutator::EliminateNull,
        &VUzzerMutator::EliminateDoubleNull,
        &VUzzerMutator::TotallyRandom,
        &VUzzerMutator::IntSlide,
        &VUzzerMutator::DoubleFuzz,
        &VUzzerMutator::ChangeRandomFull,
        &VUzzerMutator::ChangeRandomFull,
        &VUzzerMutator::EliminateRandom,
        &VUzzerMutator::AddRandom,
        &VUzzerMutator::ChangeRandom,
        &VUzzerMutator::OverwriteDictWord,
        &VUzzerMutator::InsertDictWord};
}  // namespace

const VUzzerMutator::MutCrossFunc VUzzerMutator::crossovers[] = {
    &VUzzerMutator::SingleCrossOver, &VUzzerMutator::DoubleCrossOver};
/* TODO: Implement generator class */

VUzzerMutator::VUzzerMutator(const exec_input::ExecInput &input,
                             const VUzzerState &state)
    : Mutator<typename VUzzerState::Tag>(input), state(state) {}

VUzzerMutator::~VUzzerMutator() {}

VUzzerMutator::VUzzerMutator(VUzzerMutator &&src)
    : Mutator<typename VUzzerState::Tag>(std::move(src)), state(src.state) {}

/**
 * @brief Determine the mutation offset of input buffer. The offset should be
 * less than size
 * @param (limit) upper limit of offset.
 */
u32 VUzzerMutator::GetCutPos(u32 limit) {
  u32 cut_pos = 0;
  if (state.taint_cmp_offsets.size() && rand() % 10 > 3) {
    u64 id = input.GetID();
    std::vector<std::pair<u32, std::set<u32>>> taint_choices;

    const std::set<u32> *offsets;

    if (state.taint_cmp_offsets.find(id) != state.taint_cmp_offsets.end()) {
      offsets = &(state.taint_cmp_offsets.at(id));
    } else {
      std::sample(state.taint_cmp_offsets.begin(),
                  state.taint_cmp_offsets.end(),
                  std::back_inserter(taint_choices), 1,
                  std::mt19937{std::random_device{}()});
      offsets = &(taint_choices[0].second);
    }
    std::vector<u32> offsets_within_range;
    /* TODO: MOSTCOMM, RANDOMCOMM */
    for (auto offset : *offsets)
      if (offset < limit) offsets_within_range.emplace_back(offset);

    if (offsets_within_range.size())
      cut_pos = offsets_within_range[rand() % offsets_within_range.size()];
    else
      cut_pos = limit ? rand() % limit : 0;
  } else {
    cut_pos = limit ? rand() % limit : 0;
    /* TODO: MOSTCOMM */
  }
  DEBUG("GetCutPos %u (limit %u, taint_tag %lu)", cut_pos, limit,
        state.taint_cmp_offsets.size());
  return cut_pos;
}

/**
 * @brief Delete [pos: pos+size) range of input buffer. pos is determined by
 * GetCutPos method.
 * @sa GetCutPos
 */
void VUzzerMutator::EliminateRandom() {
  u32 cut_size = std::max(1U, fuzzuf::utils::random::Random<u32>(
                                  1U, std::max(1U, (len / denominator))));
  u32 cut_pos = GetCutPos(len - cut_size);
  DEBUG("EliminateRandom [%u, %u]", cut_pos, cut_pos + cut_size - 1);
  Mutator::Delete(cut_pos, cut_size);
}

/**
 * @brief Delete [pos: pos+size) range of input buffer. pos is chosen randomly.
 */
void VUzzerMutator::EliminateRandomEnd() {
  u32 cut_size = std::max(1U, fuzzuf::utils::random::Random<u32>(
                                  1U, std::max(1U, (len / denominator))));
  u32 cut_pos = fuzzuf::utils::random::Random<u32>(len / 2, len - cut_size);
  DEBUG("EliminateRandomEnd [%u, %u]", cut_pos, cut_pos + cut_size - 1);
  Mutator::Delete(cut_pos, cut_size);
}

/**
 * @brief Run two mutations EliminateRandomEnd and EliminateRandom sequentially.
 * @sa EliminateRandomEnd
 * @sa EliminateRandom
 */
void VUzzerMutator::DoubleEliminate() {
  DEBUG("DoubleEliminate");
  EliminateRandomEnd();
  EliminateRandom();
}

/**
 * @brief Insert random bytes at [pos: pos+size) range of input buffer. pos is
 * determined by GetCutPos method.
 * @sa GetCutPos
 */
void VUzzerMutator::AddRandom() {
  u32 add_size = std::max(1U, fuzzuf::utils::random::Random<u32>(
                                  1U, std::max(1U, (len / denominator))));
  u32 add_pos = GetCutPos(len - add_size);
  auto rand_bytes =
      vuzzer::util::GenerateRandomBytesFromDict(add_size, state.all_dicts);
  DEBUG("AddRandom [%u, %u]", add_pos, add_pos + add_size - 1);
  Insert(add_pos, rand_bytes->data(), add_size);
  ChangeBytes();
}

/**
 * @brief Replace bytes at [pos: pos+size) range of input buffer with random
 * bytes. pos is determined by GetCutPos method.
 * @sa GetCutPos
 */
void VUzzerMutator::ChangeRandom() {
  u32 change_size = std::max(1U, fuzzuf::utils::random::Random<u32>(
                                     1U, std::max(1U, (len / denominator))));
  u32 change_pos = GetCutPos(len - change_size);
  auto rand_bytes =
      vuzzer::util::GenerateRandomBytesFromDict(change_size, state.all_dicts);
  DEBUG("ChangeRandom [%u, %u]", change_pos, change_pos + change_size - 1);
  Replace(change_pos, rand_bytes->data(), change_size);
  ChangeBytes();
}

/**
 * @brief Replace each bytes at offsets with random bytes. The offsets are
 * chosen from taint information.
 */
void VUzzerMutator::ChangeBytes() {
  if (state.taint_cmp_offsets.empty()) return;

  u64 id = input.GetID();
  DEBUG("ChangeBytes %llu", id);
  std::vector<std::pair<u32, std::set<u32>>> taint_choices;

  const std::set<u32> *offsets;
  if (state.taint_cmp_offsets.find(id) != state.taint_cmp_offsets.end()) {
    offsets = &(state.taint_cmp_offsets.at(id));
  } else {
    std::sample(state.taint_cmp_offsets.begin(), state.taint_cmp_offsets.end(),
                std::back_inserter(taint_choices), 1,
                std::mt19937{std::random_device{}()});
    offsets = &(taint_choices[0].second);
  }

  for (auto o : *offsets) DEBUG("0x%x, ", o);
  // TODO: Consider MOSTCOMMON
  if (offsets->size() > 0) {
    std::vector<u32> off_choices;
    std::sample(offsets->begin(), offsets->end(),
                std::back_inserter(off_choices),
                std::max(1UL, offsets->size() / 4),
                std::mt19937{std::random_device{}()});
    for (auto choice : off_choices) {
      if (choice < len) {
        DEBUG("Change offset %u", choice);
        outbuf[choice] =
            state.all_chars_dict[random() % state.all_chars_dict.size()]
                .data[0];
      }
    }
  }
}

/**
 * When fuzzer has full_bytes_dict, then insert bytes chosen from it at the
 * offset. If not but has unique_bytes_dict, then insert bytes chosen from it at
 * the offsets. Otherwirse replace bytes at offsets with random bytes generated
 * from all_dicts. The offsets are chosen from taint information.
 * @sa GetCutPos
 */
void VUzzerMutator::ChangeRandomFull() {
  u32 change_size = std::max(1U, fuzzuf::utils::random::Random<u32>(
                                     1U, std::max(1U, (len / denominator))));
  u32 change_pos = GetCutPos(len - change_size);

  if (state.full_bytes_dict.size() > 1) {
    /* Insert random bytes generated from full_bytes_dict at change_pos */
    std::vector<const dict_t *> all_dicts;
    all_dicts.emplace_back(&state.full_bytes_dict);
    auto rand_bytes =
        vuzzer::util::GenerateRandomBytesFromDict(change_size, all_dicts);
    DEBUG("Insert at [%u:%u]", change_pos, change_pos + change_size - 1);
    Insert(change_pos, rand_bytes->data(), change_size);
  } else if (state.unique_bytes_dict.size() > 2 && len > 3) {
    /* Insert words chosen from unique_bytes_dict at change_pos1 and change_pos2
     */
    std::random_device rd;
    std::default_random_engine eng(rd());
    std::uniform_int_distribution<int> distr(1, len - 1);
    auto word1 =
        &(state.unique_bytes_dict[random() % state.unique_bytes_dict.size()]
              .data);
    auto word2 =
        &(state.unique_bytes_dict[random() % state.unique_bytes_dict.size()]
              .data);
    u32 change_pos1 = distr(eng);
    u32 change_pos2 = distr(eng);
    if (change_pos1 > change_pos2) std::swap(change_pos1, change_pos2);  // sort
    DEBUG("Insert at [%u:%lu]", change_pos1, change_pos1 + word1->size());
    DEBUG("Insert at [%u:%lu]", change_pos2, change_pos2 + word2->size());
    Insert(change_pos1, word1->data(), word1->size());
    Insert(change_pos2 + word1->size(), word2->data(),
           word2->size());  // NOTICE: After first insertion, change_pos2 is
                            // shifted.
  } else {
    /* Replace bytes at [change_pos: change_pos+change_size) range of input
     * buffer with random bytes geranted from all_dicts. */
    auto rand_bytes =
        vuzzer::util::GenerateRandomBytesFromDict(change_size, state.all_dicts);
    DEBUG("Replace at [%u:%u]", change_pos, change_pos + change_size);
    Replace(change_pos, rand_bytes->data(), change_size);
  }
}

/**
 * @brief Change each bytes at random offsets to random bytes.
 */
void VUzzerMutator::SingleChangeRandom() {
  int change_cnt = fuzzuf::utils::random::Random<int>(1, 100);
  DEBUG("SingleChangeRandom %u", change_cnt);
  for (int i = 0; i < change_cnt; i++) {
    u32 change_pos = fuzzuf::utils::random::Random<u32>(0, len - 1);
    outbuf[change_pos] = fuzzuf::utils::random::Random<u8>(1, 255);
  }
}

/**
 * @brief Decrease each bytes at random offsets.
 */
void VUzzerMutator::LowerSingleRandom() {
  int change_cnt = fuzzuf::utils::random::Random<int>(1, 100);
  DEBUG("LowerSingleRandom %u", change_cnt);
  for (int i = 0; i < change_cnt; i++) {
    u32 change_pos = fuzzuf::utils::random::Random<u32>(0, len - 1);
    outbuf[change_pos] = std::max(0, outbuf[change_pos] - 1);
  }
}

/**
 * @brief Increase each bytes at random offsets.
 */
void VUzzerMutator::RaiseSingleRandom() {
  int change_cnt = fuzzuf::utils::random::Random<int>(1, 100);
  DEBUG("RaiseSingleRandom %u", change_cnt);
  for (int i = 0; i < change_cnt; i++) {
    u32 change_pos = fuzzuf::utils::random::Random<u32>(0, len - 1);
    outbuf[change_pos] = std::min(255, outbuf[change_pos] + 1);
  }
}

/**
 * @brief Replace a '\0' byte with a specified byte
 */
void VUzzerMutator::EliminateNull() {
  int start_pos = fuzzuf::utils::random::Random<int>(0, len);
  int cut_pos =
      std::distance(outbuf, std::find(outbuf + start_pos, outbuf + len, '\0'));
  DEBUG("EliminateNull %d (found \\0 at %d)", start_pos, cut_pos);
  u8 replacement[] = {'A'};  // TODO: Specify it by argument
  if ((u32)cut_pos != len) {
    Replace(cut_pos, replacement, 1);
  }
}

/**
 * @brief Replace "\0\0" bytes with specified two bytes
 */
void VUzzerMutator::EliminateDoubleNull() {
  int start_pos = fuzzuf::utils::random::Random<int>(0, len - 1);
  u8 pattern[] = {'\0', '\0'};
  u8 replacement[] = "AA";  // TODO: Specify it by argument
  auto itr = outbuf + start_pos;
  bool found = false;
  while (itr + sizeof(pattern) < outbuf + len) {
    if (std::equal(itr, std::next(itr, sizeof(pattern)), pattern,
                   std::next(pattern, sizeof(pattern)))) {
      found = true;
      break;
    }
    itr = std::find(itr + 1, outbuf + len, pattern[0]);
  }
  if (found) {
    u32 cut_pos = std::distance(outbuf, itr);
    Replace(cut_pos, replacement, sizeof(pattern));
    DEBUG("EliminateNull %d (found \\0\\0 at %d)", start_pos, cut_pos);
  } else {
    DEBUG("EliminateNull %d", start_pos);
  }
}

/**
 * @brief Replace entire input buffer with random bytes
 */
void VUzzerMutator::TotallyRandom() {
  DEBUG("TotallyRandom");
  auto rand_bytes = vuzzer::util::GenerateRandomBytesFromDict(
      fuzzuf::utils::random::Random<u32>(100, 1000), state.all_dicts);
  auto rand_bytes_ptr =
      rand_bytes
          .release();  // XXX: We should not use raw ptr instead of unique_ptr.

  delete[] outbuf;
  outbuf = rand_bytes_ptr->data();
}

/**
 * @brief Replace four bytes of input buffer with a hard-coded magic number
 */
void VUzzerMutator::IntSlide() {
  const std::vector<std::vector<u8>> slides = {{0xFF, 0xFF, 0xFF, 0xFF},
                                               {0x80, 0x00, 0x00, 0x00},
                                               {0x00, 0x00, 0x00, 0x00}};
  if (len >= 4) {
    u32 start = int_slide_pos % len;
    DEBUG("IntSlide %u", start);
    if (start > len - 4) {
      /* XXX: Can't realloc buffer allocated by new[]. We should use std::vector
       * instead of u8* for outbuf */
      u8 *new_buf = new u8[start + 4];
      std::memcpy(new_buf, outbuf, start);
      std::memcpy(new_buf + start, slides[rand() % 3].data(), 4);
      delete[] outbuf;
      outbuf = new_buf;
      len = start + 4;
    } else {
      Replace(start, slides[rand() % 3].data(), 4);
    }
    int_slide_pos += slide_step;
  } else {
    u8 *new_buf = new u8[len];
    std::memcpy(new_buf, slides[rand() % 3].data(), len);
    delete[] outbuf;
    outbuf = new_buf;
  }
}

void VUzzerMutator::OverwriteDictWord() {
  const auto dict_end = std::partition_point(
      state.extras.begin(), state.extras.end(),
      [len = len](const auto &v) { return v.data.size() <= len; });
  const auto dict_size = std::distance(state.extras.begin(), dict_end);
  const unsigned int dict_index = rand() % dict_size;
  const auto &word = state.extras[dict_index].data;
  const auto word_len = word.size();
  const int start_pos = rand() % (len - word_len + 1);
  Replace(start_pos, word.data(), word.size());
}
void VUzzerMutator::InsertDictWord() {
  const auto dict_size =
      std::distance(state.extras.begin(), state.extras.end());
  const unsigned int dict_index = rand() % dict_size;
  const auto &word = state.extras[dict_index].data;
  const int start_pos = rand() % (len + 1);
  Insert(start_pos, word.data(), word.size());
}

/**
 * @brief Run mutation methods randomly chosen twice.
 */
void VUzzerMutator::DoubleFuzz() {
  DEBUG("DoubleFuzz");
  const auto mut_cnt = state.extras.empty() ? mutators_count_without_dict
                                            : mutators_count_with_dict;
  (this->*mutators[rand() % mut_cnt])();
  (this->*mutators[rand() % mut_cnt])();
}

/**
 * @brief Run the ChangeRandomFull mutation twice
 * @sa ChangeRandomFull
 */
void VUzzerMutator::DoubleFullMutate() {
  DEBUG("DoubleFullMutate");
  ChangeRandomFull();
  ChangeRandomFull();
}

/**
 * @brief Insert buf into [pos, pos+extra_len) of input buffer while overwriting
 * input buffer[pos] with buf[0].
 */
void VUzzerMutator::InsertWithOnebyteOverwrite(u32 pos, const u8 *buf,
                                               u32 extra_len) {
  u8 *new_buf = new u8[len + extra_len - 1];
  /* Head */
  std::memcpy(new_buf, outbuf, pos);

  /* Inserted part */
  std::memcpy(new_buf + pos, buf, extra_len);

  /* Tail */
  std::memcpy(new_buf + pos + extra_len, outbuf + pos + 1, len - pos - 1);

  delete[] outbuf;
  outbuf = new_buf;
  len += extra_len - 1;
}

/**
 * Replace random four bytes at offsets chosen from taint information about LEA
 * operations with hard-coded magic bytes. Then replace random bytes at offsets
 * chosen from taint information about CMP operations with magic bytes.
 * @brief Replace each bytes at offsets with random bytes. The offsets are
 * chosen from taint information.
 * @sa InsertWithOnebyteOverwrite
 * @todo Implement MORECOMM/MOSTCOMM modes.
 * @todo Consider worst case of time complexity. Currently it would call heavy
 * memory operation, InsertWithOnebyteOverwrite, at every changes based on taint
 * info.
 */
void VUzzerMutator::TaintBasedChange() {
  u64 id = input.GetID();
  std::vector<std::vector<u8>> values = {{0xff, 0xff, 0xff, 0xff},
                                         {0xFE, 0xFF, 0xFF, 0xFF},
                                         {0xFE, 0xFF},
                                         {0xFF, 0xFE},
                                         {0x80, 0x00, 0x00, 0x00},
                                         {0x7F, 0xFF}};

  /* Choose some offsets from taint info about LEA operation. */
  if (state.taint_lea_offsets.find(id) != state.taint_lea_offsets.end()) {
    auto &offsets_set = state.taint_lea_offsets.at(id);
    if (offsets_set.size() > 0) {
      std::vector<u32> off_choices;
      std::sample(offsets_set.begin(), offsets_set.end(),
                  std::back_inserter(off_choices),
                  std::max(1UL, offsets_set.size() / 2),
                  std::mt19937{std::random_device{}()});
      for (auto choice : off_choices) {
        if (choice < len) {
          std::vector<u8> value = values[random() % values.size()];
          InsertWithOnebyteOverwrite(choice, value.data(), value.size());
        }
      }
    }
  }

  /* Choose some offsets from taint info about CMP operation. */
  if (state.taint_cmp_all.find(id) != state.taint_cmp_all.end()) {
    auto &offsets_map = state.taint_cmp_all.at(id);
    if (offsets_map.size() > 0) {
      std::vector<std::pair<u32, std::vector<u32>>>
          off_choices;  // [(off1, [v1_1, v1_2...]), ....]
      std::sample(offsets_map.rbegin(), offsets_map.rend(),
                  std::back_inserter(off_choices),
                  std::max(1UL, offsets_map.size() / 2),
                  std::mt19937{std::random_device{}()});
      for (auto choice : off_choices) {
        u32 offset = choice.first;
        if (offset < len) {
          // TODO: MOSTCOMMLAST
          u32 value = choice.second.at(random() % choice.second.size());
          // outbuf[offset] = value;//XXX
          //  Convert u32 value to bytes in a little endian
          //  manner(extract_offsetStr, get_hexStr in VUzzer)
          //  TODO: Move to Util
          u32 size = 0;
          u8 *bytes;
          if (value == 0) {
            size = 1;
            bytes = new u8[size];
            bytes[0] = 0;
          } else {
            for (u32 v = value; v; v >>= 8) size++;
            bytes = new u8[size];
            for (u32 v = value, i = 0; v; v >>= 8, i++) bytes[i] = v & 0xff;
          }
          DEBUG("Change %u", offset);
          InsertWithOnebyteOverwrite(offset, bytes, size);
          delete[] bytes;
        }
      }
    }
  }

  /* TODO: MORECOMM, MOSTCOMM */
}

/* FIXME: We must not use ExecInputSet for return value of crossover:(
    Currently crossover mutator generates new seeds and put them into
   ExecInputSet. However ExecInputSet should only be used for the purpose of
   saving seeds in seed_queues. */
/**
 * @brief Cut the two inputs at each offsets and swap them.
 * @param (target) XXX
 */
std::pair<std::shared_ptr<exec_input::ExecInput>,
          std::shared_ptr<exec_input::ExecInput>>
VUzzerMutator::SingleCrossOver(const exec_input::ExecInput &target) {
  std::unique_ptr<exec_input::ExecInputSet> input_set(
      new exec_input::ExecInputSet());
  std::random_device rd;
  std::default_random_engine eng(rd());
  std::uniform_real_distribution<> distr(0.1, 0.6);
  u32 len1 = len, len2 = target.GetLen();
  u8 *buf1 = outbuf, *buf2 = target.GetBuf();

  double point = distr(eng);

  u32 cut_pos1 = point * len1;
  u32 cut_pos2 = point * len2;

  u32 new_len1 = cut_pos1 + (len2 - cut_pos2);
  u32 new_len2 = cut_pos2 + (len1 - cut_pos1);

  DEBUG("SingleCrossOver %u, %u", cut_pos1, cut_pos2);
  std::unique_ptr<u8[]> new_buf1(new u8[new_len1]);
  std::unique_ptr<u8[]> new_buf2(new u8[new_len2]);

  std::memcpy(new_buf1.get(), buf1, cut_pos1);
  std::memcpy(new_buf1.get() + cut_pos1, buf2 + cut_pos2, len2 - cut_pos2);
  std::memcpy(new_buf2.get(), buf2, cut_pos2);
  std::memcpy(new_buf2.get() + cut_pos2, buf1 + cut_pos1, len1 - cut_pos1);

  auto new_seed1 = input_set->CreateOnMemory(std::move(new_buf1), new_len1);
  auto new_seed2 = input_set->CreateOnMemory(std::move(new_buf2), new_len2);

  return std::make_pair(new_seed1, new_seed2);
}

/**
 * @brief Pick up subsets from two inputs and swap them.
 * @param (target) XXX
 */
std::pair<std::shared_ptr<exec_input::ExecInput>,
          std::shared_ptr<exec_input::ExecInput>>
VUzzerMutator::DoubleCrossOver(const exec_input::ExecInput &target) {
  std::unique_ptr<exec_input::ExecInputSet> input_set(
      new exec_input::ExecInputSet());
  std::random_device rd;
  std::default_random_engine eng(rd());
  std::uniform_real_distribution<> distr1(0.1, 0.3), distr2(0.6, 0.8);

  u32 len1 = len, len2 = target.GetLen();
  u8 *buf1 = outbuf, *buf2 = target.GetBuf();

  double point1 = distr1(eng), point2 = distr2(eng);
  u32 cut_pos11 = point1 * len1;
  u32 cut_pos12 = point2 * len1;
  u32 cut_pos21 = point1 * len2;
  u32 cut_pos22 = point2 * len2;

  u32 new_len1 = cut_pos11 + (cut_pos22 - cut_pos21) + (len1 - cut_pos12);
  u32 new_len2 = cut_pos21 + (cut_pos12 - cut_pos11) + (len2 - cut_pos22);

  std::unique_ptr<u8[]> new_buf1(new u8[new_len1]);
  std::unique_ptr<u8[]> new_buf2(new u8[new_len2]);

  DEBUG("DoubleCrossOver %u, %u, %u, %u", cut_pos11, cut_pos12, cut_pos21,
        cut_pos22);

  std::memcpy(new_buf1.get(), buf1, cut_pos11);
  std::memcpy(new_buf1.get() + cut_pos11, buf2 + cut_pos21,
              cut_pos22 - cut_pos21);
  std::memcpy(new_buf1.get() + cut_pos11 + (cut_pos22 - cut_pos21),
              buf1 + cut_pos12, len1 - cut_pos12);

  std::memcpy(new_buf2.get(), buf2, cut_pos21);
  std::memcpy(new_buf2.get() + cut_pos21, buf1 + cut_pos11,
              cut_pos12 - cut_pos11);
  std::memcpy(new_buf2.get() + cut_pos21 + (cut_pos12 - cut_pos11),
              buf2 + cut_pos22, len2 - cut_pos22);

  auto new_seed1 = input_set->CreateOnMemory(std::move(new_buf1), new_len1);
  auto new_seed2 = input_set->CreateOnMemory(std::move(new_buf2), new_len2);

  return std::make_pair(new_seed1, new_seed2);
}

/**
 * @brief Run mutation methods randomly chosen
 */
void VUzzerMutator::MutateRandom() {
  const auto mut_cnt = state.extras.empty() ? mutators_count_without_dict
                                            : mutators_count_with_dict;
  (this->*mutators[rand() % mut_cnt])();
  while (len < 3) {
    (this->*mutators[rand() % mut_cnt])();
  }
  assert(len > 2);
}

/**
 * @brief Run crossover mutation methods randomly chosen
 * @param (target) XXX
 */
std::pair<std::shared_ptr<exec_input::ExecInput>,
          std::shared_ptr<exec_input::ExecInput>>
VUzzerMutator::CrossOver(const exec_input::ExecInput &target) {
  u32 mut_cnt = sizeof(crossovers) / sizeof(MutCrossFunc);
  return (this->*crossovers[rand() % mut_cnt])(target);
}

}  // namespace fuzzuf::algorithm::vuzzer
