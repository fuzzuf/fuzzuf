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

#include "fuzzuf/executor/proxy_executor.hpp"

namespace fuzzuf::executor {
// A class for fuzz executions with CoreSight
class CoreSightExecutor : public ProxyExecutor {
 public:
  CoreSightExecutor(
      const fs::path &proxy_path, const std::vector<std::string> &argv,
      u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
      const fs::path &path_to_write_input, u32 afl_shm_size,
      // FIXME: see the comment for the same variable in NativeLinuxExecutor
      bool record_stdout_and_err);
};
}  // namespace fuzzuf::executor
