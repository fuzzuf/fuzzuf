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
 * @file VUzzerState.hpp
 * @brief Global state used during hieraflow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <algorithm>
#include <boost/dynamic_bitset.hpp>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_setting.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_testcase.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/executor/polytracker_executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

using AFLDictData = fuzzuf::algorithm::afl::dictionary::AFLDictData;
using dict_t = std::vector<AFLDictData>;

namespace fuzzuf::algorithm::vuzzer {

struct VUzzerState {
  using Tag = typename VUzzerTestcase::Tag;

  // FIXME: how to support other executors?
  explicit VUzzerState(
      std::shared_ptr<const VUzzerSetting> setting,
      std::shared_ptr<fuzzuf::executor::PinToolExecutor> executor,
      std::shared_ptr<fuzzuf::executor::PolyTrackerExecutor> texecutor);
  ~VUzzerState();

  VUzzerState(const VUzzerState &) = delete;
  VUzzerState &operator=(const VUzzerState &) = delete;

  feedback::FileFeedback RunExecutor(const u8 *buf, u32 len,
                                     feedback::ExitStatusFeedback &exit_status,
                                     u32 tmout = 0);

  feedback::FileFeedback RunTaintExecutor(
      const u8 *buf, u32 len, feedback::ExitStatusFeedback &exit_status,
      u32 tmout = 0);

  void ReceiveStopSignal(void);
  void ReadTestcases(void);
  std::shared_ptr<VUzzerTestcase> AddToQueue(
      std::vector<std::shared_ptr<VUzzerTestcase>> &queue,
      const std::string &fn, const u8 *buf, u32 len);

  std::vector<std::shared_ptr<VUzzerTestcase>>::iterator DeleteFromQueue(
      std::vector<std::shared_ptr<VUzzerTestcase>> &queue,
      std::vector<std::shared_ptr<VUzzerTestcase>>::iterator &itr);

  std::shared_ptr<const VUzzerSetting> setting;
  std::shared_ptr<fuzzuf::executor::PinToolExecutor> executor;
  std::shared_ptr<fuzzuf::executor::PolyTrackerExecutor> taint_executor;

  exec_input::ExecInputSet input_set;

  u32 queued_paths = 0;   /* Total number of queued testcases */
  u64 unique_crashes = 0; /* Crashes with unique signatures   */

  // these will be required in ShowStats
  // (originally, these are defined as its static variables)
  u64 last_ms = 0;
  u64 last_execs = 0;
  u64 last_plot_ms = 0;
  u64 last_stats_ms = 0;
  double avg_exec = 0.0;

  u64 loop_cnt = 0;         /* Total fuzz loop count            */
  u8 stop_soon = 0;         /* Ctrl-C pressed?                  */
  bool clear_screen = true; /* Window resized?                  */

  bool errorbb =
      true; /* this flag decides if we want to run error BB detection step. */
  bool has_new_cov = false; /* this flag is set on when new seeds which records
                               new coverage appear */
  u32 gennum = 1000;        /* number of iterations (generations) to run GA */
  u32 bbslide = 40;
  u32 keepslide = 3;
  u32 keepfilenum;

  /* Fuzzing queues */
  std::vector<std::shared_ptr<VUzzerTestcase>>
      seed_queue;  // seeds which have already executed and evaluated.
  std::vector<std::shared_ptr<VUzzerTestcase>>
      pending_queue;  // seeds which have not evaluated yet
  std::vector<std::shared_ptr<VUzzerTestcase>>
      keep_queue;  // seeds which should be keeped
  std::vector<std::shared_ptr<VUzzerTestcase>>
      taint_queue;  // seeds which should be executed by taint engine

  /* Seed <--> BB cov mapping */
  std::map<u64, boost::dynamic_bitset<>> bb_covs;

  /* EHB addrs */
  std::set<u64> ehb;      // EHB addresses detected while initial analysis
  std::set<u64> ehb_inc;  // EHB addresses detected while incremental analysis

  /* BB addrs */
  std::set<u64> seen_bbs;
  std::vector<u64> seen_bbs_table_for_bits;  // It's used when converted to bits
  std::set<u64> good_bbs;

  /* BB weights */
  std::map<u64, u32> bb_weights;  // config.ALLBB

  /* Crash hashes */
  std::set<std::string> crash_hashes;

  dict_t full_bytes_dict;
  dict_t unique_bytes_dict;
  dict_t all_chars_dict;
  dict_t high_chars_dict;

  std::vector<const dict_t *> all_dicts;

  /* Taint tags */
  std::map<u64, std::map<u32, std::vector<u32>>> taint_cmp_all;
  std::map<u64, std::set<u32>> taint_cmp_offsets;
  std::map<u64, std::set<u32>> taint_lea_offsets;

  using AFLDictData = afl::dictionary::AFLDictData;
  /* Extra tokens to fuzz with        */
  std::vector<AFLDictData> extras;
};

}  // namespace fuzzuf::algorithm::vuzzer
