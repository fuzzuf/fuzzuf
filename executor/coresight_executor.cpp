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
#include "fuzzuf/executor/coresight_executor.hpp"

#include "fuzzuf/utils/check_crash_handling.hpp"

namespace fuzzuf::executor {
/**
 * Precondition:
 *    - A file can be created at path path_str_to_write_input.
 */
CoreSightExecutor::CoreSightExecutor(const fs::path &proxy_path,
                                     const std::vector<std::string> &argv,
                                     u32 exec_timelimit_ms, u64 exec_memlimit,
                                     bool forksrv,
                                     const fs::path &path_to_write_input,
                                     u32 afl_shm_size,
                                     bool record_stdout_and_err)
    : ProxyExecutor(proxy_path, std::vector<std::string>(), argv,
                    exec_timelimit_ms, exec_memlimit, forksrv,
                    path_to_write_input, afl_shm_size, record_stdout_and_err) {
  fuzzuf::utils::CheckCrashHandling();

  ProxyExecutor::SetCArgvAndDecideInputMode();
  ProxyExecutor::Initilize();
}
}  // namespace fuzzuf::executor
