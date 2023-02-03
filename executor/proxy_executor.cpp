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
#include "fuzzuf/executor/proxy_executor.hpp"

namespace fuzzuf::executor {
// Precondition:
//    - A file can be created at path path_str_to_write_input.
//    - If fork server mode, proxy specified by proxy_path behave as fork
//    server.
//    - The derived class constructor is responsible for initializing cargv and
//    stdin_mode.
ProxyExecutor::ProxyExecutor(const fs::path &proxy_path,
                             const std::vector<std::string> &pargv,
                             const std::vector<std::string> &argv,
                             u32 exec_timelimit_ms, u64 exec_memlimit,
                             bool forksrv, const fs::path &path_to_write_input,
                             u32 afl_shm_size, bool record_stdout_and_err)
    : BaseProxyExecutor(proxy_path, pargv, argv, exec_timelimit_ms,
                        exec_memlimit, forksrv, path_to_write_input,
                        record_stdout_and_err),
      afl_edge_coverage(afl_shm_size) {
  if (afl_edge_coverage.GetMapSize() > 0) has_shared_memories = true;
}

u32 ProxyExecutor::GetAFLMapSize() { return afl_edge_coverage.GetMapSize(); }

int ProxyExecutor::GetAFLShmID() { return afl_edge_coverage.GetShmID(); }

feedback::InplaceMemoryFeedback ProxyExecutor::GetAFLFeedback() {
  return afl_edge_coverage.GetFeedback();
}

bool ProxyExecutor::IsFeedbackLocked() {
  return (lock.use_count() > 1) || (afl_edge_coverage.GetLockUseCount() > 1);
}

// Initialize shared memory group that the PUT writes the coverage.
// These shared memory is reused for all PUTs (It is too slow to allocate for
// each PUT).
void ProxyExecutor::SetupSharedMemories() { afl_edge_coverage.Setup(); }

// Since shared memory is reused, it is initialized every time before passed to
// PUT.
void ProxyExecutor::ResetSharedMemories() { afl_edge_coverage.Reset(); }

// Delete SharedMemory when the Executor is deleted
void ProxyExecutor::EraseSharedMemories() { afl_edge_coverage.Erase(); }

// Since PUT that is instrumented using afl-clang-fast or fuzzuf-cc
// interprets some environment variables, this is the configuration for it.
// Although, this is actually what the child process running PUT should do,
// since there are no environment variables need update for each PUT execution
// for now, by using feature that environment variables are inherited to child
// process, it is enough to do just once ( let's move it if not ). As the
// additional advantage, it can avoid to waste Copy on Write of heap region due
// to StrPrintf.
void ProxyExecutor::SetupEnvironmentVariablesForTarget() {
  // Pass the id of shared memory to PUT.
  afl_edge_coverage.SetupEnvironmentVariable();

  BaseProxyExecutor::SetupEnvironmentVariablesForTarget();
}
}  // namespace fuzzuf::executor
