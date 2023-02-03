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
 * @file VUzzerUtil.cpp
 * @brief Utility functions for VUzzer
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/vuzzer/vuzzer_util.hpp"

#include <sstream>

#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::vuzzer::util {

/**
 * @brief Parse basic block weight file.
 * @param (state) VUzzer state
 * @param (path) Path to bb weight file
 */
void ParseBBWeights(VUzzerState& state, const fs::path& path) {
  /* Weight file format
   * addr weight
   * addr is address of BB
   * weight is score of BB calculated by static analysis tool. (BB-weight.py)
   */

  std::string off_raw, line;

  int off_fd = fuzzuf::utils::OpenFile(path.native(), O_RDONLY);

  struct stat sb {};

  fstat(off_fd, &sb);
  off_raw.resize(sb.st_size);

  fuzzuf::utils::ReadFile(off_fd, (u8*)(off_raw.data()), sb.st_size);
  fuzzuf::utils::CloseFile(off_fd);

  std::stringstream off_stream{off_raw};

  while (std::getline(off_stream, line)) {
    std::stringstream line_stream(line);
    std::string token;
    std::vector<std::string> tokens;
    while (std::getline(line_stream, token, ' ')) tokens.emplace_back(token);

    if (tokens.size() != 3)
      throw -1;  // XXX: Implment exception class for parse error;

    u32 addr = strtol(tokens[0].c_str(), NULL, 16);
    u32 weight = strtol(tokens[1].c_str(), NULL, 16);
    state.bb_weights[addr] = weight;
  }
}

/**
 * @brief Parse basic block coverage file.
 * @param (inp_feed) FileFeedback obtained by PUT execution
 * @param (bb_cov) A result of the parsing
 */
void ParseBBCov(feedback::FileFeedback& inp_feed, std::map<u64, u32>& bb_cov) {
  /* BB coverage file format
   * addr count
   * addr is address of BB.
   * count is
   */
  std::string feed_raw, line;
  fs::path feed_path = inp_feed.feed_path.native();

  int feed_fd = fuzzuf::utils::OpenFile(feed_path.native(), O_RDONLY);

  struct stat sb {};

  fstat(feed_fd, &sb);
  feed_raw.resize(sb.st_size);

  fuzzuf::utils::ReadFile(feed_fd, (u8*)(feed_raw.data()), sb.st_size);
  fuzzuf::utils::CloseFile(feed_fd);

  std::stringstream feed_stream{feed_raw};

  while (std::getline(feed_stream, line)) {
    std::stringstream line_stream(line);
    std::string token;
    std::vector<std::string> tokens;
    while (std::getline(line_stream, token, ' ')) tokens.emplace_back(token);

    if (tokens.size() != 2)
      throw -1;  // XXX: Implment exception class for parse error;

    u64 addr = strtoll(tokens[0].c_str(), NULL, 16);
    u32 cnt = strtol(tokens[1].c_str(), NULL, 16);
    bb_cov[addr] = cnt;
  }
}

/**
 * @brief Parse taint file.
 * @param (state) VUzzer state
 * @param (testcase)
 * @param (inp_feed) FileFeedback obtained by PUT execution
 */
void ParseTaintInfo(VUzzerState& state,
                    const std::shared_ptr<VUzzerTestcase>& testcase,
                    feedback::FileFeedback& inp_feed) {
  /* Taint file format
   * CMP|LEA o1,o2,o3...o_n v1,v2,v3...v_m
   * o_n is offsets touched by cmp/lea op.
   * v_m is values referred by cmp/lea op.
   */
  u64 id = testcase->input->GetID();
  std::string feed_raw, line;
  fs::path feed_path = inp_feed.feed_path.native();

  int feed_fd = fuzzuf::utils::OpenFile(feed_path.native(), O_RDONLY);

  struct stat sb {};

  fstat(feed_fd, &sb);
  feed_raw.resize(sb.st_size);

  fuzzuf::utils::ReadFile(feed_fd, (u8*)(feed_raw.data()), sb.st_size);
  fuzzuf::utils::CloseFile(feed_fd);

  std::stringstream feed_stream{feed_raw};

  while (std::getline(feed_stream, line)) {
    std::stringstream line_stream(line);
    std::string token;
    std::vector<std::string> tokens;
    while (std::getline(line_stream, token, ' ')) tokens.emplace_back(token);

    if (tokens.size() != 3)
      throw -1;  // XXX: Implment exception class for parse error;

    std::stringstream off_stream(tokens[1]);
    std::stringstream val_stream(tokens[2]);
    std::string off_str, val_str;

    std::getline(off_stream, off_str, ',');  // Take only offsets[0]
    u32 offset = strtol(off_str.c_str(), NULL, 16);

    if (tokens[0] == "CMP") {
      std::vector<u32> values;
      while (std::getline(val_stream, val_str, ',')) {
        u32 value = strtol(val_str.c_str(), NULL, 16);
        values.emplace_back(value);
      }
      state.taint_cmp_all[id][offset] = values;
      state.taint_cmp_offsets[id].insert(offset);

      for (auto v : values)
        DEBUG("taint_cmp_all[%llu][0x%x] = 0x%x", id, offset, v);

    } else if (tokens[0] == "LEA") {
      state.taint_lea_offsets[id].insert(offset);
    } else {
      throw -1;
    }
  }
}

/**
 * Convert dictionary {0xXXXXX: i} to bitsets format 0x10001000.... based on the
 * global key set. If i-th key of global key set exists in dictionary, then i-th
 * bit is set.
 * @brief Convert dictionary {0xXXXXX: i} to bitsets format 0x10001000... based
 * on the global key set.
 * @param (dict) Dictionary
 * @param (keys) Global key set
 * @param (bits) Bitsets
 */
void DictToBitsWithKeys(std::map<u64, u32>& dict, std::vector<u64>& keys,
                        boost::dynamic_bitset<>& bits) {
  for (const auto& d : dict) {
    u64 key = d.first;
    auto itr = std::find(keys.begin(), keys.end(), key);
    /* If global key set has not had the key yet, it's added. */
    if (itr == keys.end()) keys.emplace_back(key);
  }

#if 0
    DEBUG("Global Key Set");
    for (auto &k : keys) {
        DEBUG("0x%llx, ",k);
    }
#endif

  bits.resize(keys.size());
  for (const auto& d : dict) {
    u64 key = d.first;
    auto itr = std::find(keys.begin(), keys.end(), key);
    int idx = std::distance(keys.begin(), itr);
    bits.set(idx);
  }
  // std::cout<<bits<<std::endl;
}

/* Generate random n-bytes string from dictionaries */
std::unique_ptr<std::vector<u8>> GenerateRandomBytesFromDict(
    u32 size, const std::vector<const dict_t*>& all_dicts) {
  std::unique_ptr<std::vector<u8>> result(new std::vector<u8>);
  while (result->size() < size) {
    auto& dict = all_dicts[random() % all_dicts.size()];
    const AFLDictData& word = dict->at(random() % dict->size());
    result->insert(result->end(), word.data.begin(), word.data.end());
  }
  return result;
}

}  // namespace fuzzuf::algorithm::vuzzer::util
