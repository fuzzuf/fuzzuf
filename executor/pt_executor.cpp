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
#include "fuzzuf/executor/pt_executor.hpp"

#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/check_crash_handling.hpp"

namespace fuzzuf::executor {
// NOTE:
//    - PTExecutor assume it can create a file at `path_to_write_input`.
PTExecutor::PTExecutor(const fs::path &proxy_path,
                       const std::vector<std::string> &argv,
                       u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
                       const fs::path &path_to_write_input,
                       bool record_stdout_and_err)
    : BaseProxyExecutor(proxy_path, std::vector<std::string>(), argv,
                        exec_timelimit_ms, exec_memlimit, forksrv,
                        path_to_write_input, record_stdout_and_err),
      afl_pt_path_coverage(PTExecutor::PATH_SHM_SIZE),
      afl_pt_path_fav(PTExecutor::FAV_SHM_SIZE) {
  fuzzuf::utils::CheckCrashHandling();

  if (afl_pt_path_coverage.GetMapSize() > 0 ||
      afl_pt_path_fav.GetMapSize() > 0) {
    has_shared_memories = true;
  }

  BaseProxyExecutor::SetCArgvAndDecideInputMode();
  BaseProxyExecutor::Initilize();
}

void PTExecutor::SetupSharedMemories() {
  afl_pt_path_coverage.Setup();
  afl_pt_path_fav.Setup();
}

void PTExecutor::ResetSharedMemories() {
  afl_pt_path_coverage.Reset();
  afl_pt_path_fav.Reset();
}

void PTExecutor::EraseSharedMemories() {
  afl_pt_path_coverage.Erase();
  afl_pt_path_fav.Erase();
}

void PTExecutor::SetupEnvironmentVariablesForTarget() {
  afl_pt_path_coverage.SetupEnvironmentVariable();
  afl_pt_path_fav.SetupEnvironmentVariable();

  BaseProxyExecutor::SetupEnvironmentVariablesForTarget();
}

feedback::InplaceMemoryFeedback PTExecutor::GetPathFeedback() {
  return afl_pt_path_coverage.GetFeedback();
}

feedback::InplaceMemoryFeedback PTExecutor::GetFavFeedback() {
  return afl_pt_path_fav.GetFeedback();
}

bool PTExecutor::IsFeedbackLocked() {
  return (lock.use_count() > 1) ||
         (afl_pt_path_coverage.GetLockUseCount() > 1) ||
         (afl_pt_path_fav.GetLockUseCount() > 1);
}
}  // namespace fuzzuf::executor
