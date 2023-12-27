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

#include <bitset>
#include <memory>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"

namespace fuzzuf::algorithm::afl {

struct AFLTestcase {
  using Tag = option::AFLTag;

  explicit AFLTestcase(std::shared_ptr<exec_input::OnDiskExecInput> input);
  virtual ~AFLTestcase();

  bool WasFuzzed(void) const;
  void MarkFuzzed(void);

  std::shared_ptr<exec_input::OnDiskExecInput> input;

  u8 cal_failed = 0;         /* Calibration failed?              */
  bool trim_done = false;    /* Trimmed?                         */
  bool was_fuzzed = false;   /* Had any fuzzing done yet?        */
  bool was_fuzzed2 = false;  /* Had any fuzzing done yet?        */
  bool passed_det = false;   /* Deterministic stages passed?     */
  bool has_new_cov = false;  /* Triggers new coverage?           */
  bool var_behavior = false; /* Variable behavior?               */
  bool favored = false;      /* Currently favored?               */
  u8 cnt_free_cksum_dup = 0;
  bool fs_redundant = false; /* Marked as redundant in the fs?   */

  u32 qid;             /* queue id for current item        */
  u32 bitmap_size = 0; /* Number of bits set in bitmap     */
  u32 fuzz_level = 0;  /* Number of fuzzing iterations     */
  u32 cnt_free_cksum = 0;  /* Checksum of the execution trace  */
  u32 exec_cksum = 0;  /* Checksum of the execution trace  */
  u32 init_perf_score = 100;

  u64 exec_us = 0;  /* Execution time (us)              */
  u64 handicap = 0; /* Number of queue cycles behind    */
  u64 depth = 0;    /* Path depth                       */

  /* Trace bytes, if kept             */
  std::unique_ptr<std::bitset<option::GetMapSize<Tag>()>> trace_mini;

  u32 tc_ref = 0; /* Trace bytes ref count            */
  std::vector< u32 > border_edge;  /* list of border_edge IDX */
  u32 border_edge_cnt = 0u;  /* total number of local border_edge*/
  double thres_energy = 0.0;
};

void to_json( nlohmann::json&, const AFLTestcase& );
void dump_testcase_if_verbose( const std::string &header, const AFLTestcase &testcase );

}  // namespace fuzzuf::algorithm::afl
