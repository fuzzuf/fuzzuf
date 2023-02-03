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

#include "fuzzuf/coverage/afl_edge_cov_attacher.hpp"
#include "fuzzuf/executor/base_proxy_executor.hpp"

namespace fuzzuf::executor {
// A class for fuzz execution under Linux environment through proxies (such as
// QEMU) having fork server.
//
// Responsibility:
//  - Class member Executor::argv must hold the information required for an
//  execution of the fuzzing target process (e.g. command, arguments)
//  - A class member ProxyExecutor::proxy_path must hold the path to the proxy
//  which is going to be executed
//  - A class member ProxyExecutor::pargv must hold the information required for
//  an execution of the proxy (e.g. arguments)
//
// Responsibility (TODO):
//  - The lifetime for the class itself and the time period of validity of
//  member variables must match (TODO because checks have not completed)
//      - This is to ensure the robustness
class ProxyExecutor : public BaseProxyExecutor {
 public:
  coverage::AFLEdgeCovAttacher afl_edge_coverage;

  ProxyExecutor(
      const fs::path &proxy_path, const std::vector<std::string> &pargv,
      const std::vector<std::string> &argv, u32 exec_timelimit_ms,
      u64 exec_memlimit, bool forksrv, const fs::path &path_to_write_input,
      u32 afl_shm_size,
      // FIXME: The below is a temporary flag to avoid a big performance issue.
      // The issue appears when we save the outputs of stdout/stderr to buffers
      // in every execution of a PUT, which isn't required in most fuzzers.
      // This is just a temporary and ugly countermeasure.
      // In the future, we should generalize this flag so that we can
      // arbitrarily specify which fd should be recorded. For example, by
      // passing std::vector<int>{1, 2} to this class, we would tell that we
      // would like to record stdout and stderr.
      bool record_stdout_and_err = false);

  // Environment-specific methods
  u32 GetAFLMapSize();
  int GetAFLShmID();

  feedback::InplaceMemoryFeedback GetAFLFeedback();

  virtual bool IsFeedbackLocked() override;

  virtual void SetupSharedMemories() override;
  virtual void ResetSharedMemories() override;
  virtual void EraseSharedMemories() override;
  virtual void SetupEnvironmentVariablesForTarget() override;
};
}  // namespace fuzzuf::executor
