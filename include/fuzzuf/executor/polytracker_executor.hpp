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
 * @file PolyTrackerExecutor.hpp
 * @brief Executor for dynamic taint analysis tool, polytracker
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include "fuzzuf/executor/base_proxy_executor.hpp"

namespace fuzzuf::executor {
class PolyTrackerExecutor : public BaseProxyExecutor {
 public:
  const std::string path_str_to_executor;  // Path to executor bin
  const std::string path_str_to_db;        // Path to taint database
  const std::string path_str_to_inst_bin;  // Path to instrumented PUT
  const std::string
      path_str_to_output;   // Path to output of polytracker_executor, cmp.out
                            // and lea.out
  std::string cmdline_str;  // Cmdline string for PUT execution

  PolyTrackerExecutor(const fs::path &path_to_executor,
                      const fs::path &path_to_inst_bin,
                      const fs::path &path_to_db,
                      const fs::path &path_to_output,
                      const std::vector<std::string> &argv,
                      u32 exec_timelimit_ms, u64 exec_memlimit,
                      const fs::path &path_to_write_input);

  void SetCArgvAndDecideInputMode();
};
}  // namespace fuzzuf::executor
