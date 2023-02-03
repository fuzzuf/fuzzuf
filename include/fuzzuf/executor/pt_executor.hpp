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

#include "fuzzuf/coverage/afl_pt_path_cov_attacher.hpp"
#include "fuzzuf/coverage/afl_pt_path_fav_attacher.hpp"
#include "fuzzuf/executor/base_proxy_executor.hpp"

namespace fuzzuf::executor {
// A class for fuzz executions with Intel PT
// NOTE:
// This executor provides path coverage feedback introduced in PTrix
// (https://arxiv.org/pdf/1905.10499.pdf). The original PTrix implementation
// uses two bitmaps: trace_bits and pt_fav_bits. trace_bits records the last TIP
// IP hash value in the current context represented as one bit. This trace_bits
// semantics is quite different from the traditional AFL edge coverage, so we
// cannot use the trace_bits for calculating top_rated[] on AFL. The PTrix
// implementation introduces pt_fav_bits to calculate top_rated[]. From the
// above reasons, we should consider renaming trace_bits so that fuzzers can
// distinguish the shared memory semantics.
// https://github.com/junxzm1990/afl-pt/blob/master/afl-2.42b/pt-fuzz-fast.c#L1226-#L1229
class PTExecutor : public BaseProxyExecutor {
 public:
  // shm_size is fixed in PTrix pt-proxy-fast.
  static constexpr u32 PATH_SHM_SIZE = (1U << 16);
  static constexpr u32 FAV_SHM_SIZE = (1U << 16);

  coverage::AFLPTPathCovAttacher afl_pt_path_coverage;
  coverage::AFLPTPathFavAttacher afl_pt_path_fav;

  PTExecutor(
      const fs::path &proxy_path, const std::vector<std::string> &argv,
      u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
      const fs::path &path_to_write_input,
      // FIXME: see the comment for the same variable in NativeLinuxExecutor
      bool record_stdout_and_err = false);

  feedback::InplaceMemoryFeedback GetPathFeedback();
  feedback::InplaceMemoryFeedback GetFavFeedback();

  bool IsFeedbackLocked() override;

  void SetupSharedMemories() override;
  void ResetSharedMemories() override;
  void EraseSharedMemories() override;
  void SetupEnvironmentVariablesForTarget() override;
};
}  // namespace fuzzuf::executor
