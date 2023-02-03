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
 * @file PolyTrackerExecutor.cpp
 * @brief Executor for dynamic taint analysis tool, polytracker
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/executor/polytracker_executor.hpp"

#include <sstream>

#include "fuzzuf/utils/check_crash_handling.hpp"

namespace fuzzuf::executor {
PolyTrackerExecutor::PolyTrackerExecutor(
    const fs::path &path_to_executor, const fs::path &path_to_inst_bin,
    const fs::path &path_to_db, const fs::path &path_to_output,
    const std::vector<std::string> &argv, u32 exec_timelimit_ms,
    u64 exec_memlimit, const fs::path &path_to_write_input)
    : BaseProxyExecutor(argv, exec_timelimit_ms, exec_memlimit,
                        path_to_write_input),
      path_str_to_executor(path_to_executor.string()),
      path_str_to_db(path_to_db.string()),
      path_str_to_inst_bin(path_to_inst_bin.string()),
      path_str_to_output(path_to_output.string()) {
  fuzzuf::utils::CheckCrashHandling();

  SetCArgvAndDecideInputMode();
  BaseProxyExecutor::Initilize();
}

void PolyTrackerExecutor::SetCArgvAndDecideInputMode() {
  assert(!argv.empty());

  stdin_mode = true;  // if we find @@, then assign false to stdin_mode

  for (const auto &v : argv) {
    if (v == "@@") stdin_mode = false;
  }

  /* Transform argv vectors to string. argv[0] is replaced to the path to
   * instrumented PUT */
  std::ostringstream os;
  const char *delim = " ";
  std::copy(std::next(argv.begin(), 1), argv.end(),
            std::ostream_iterator<std::string>(os, delim));
  std::string tmp = os.str();
  tmp.erase(tmp.size() -
            std::char_traits<char>::length(delim));  // Remove tail delimitaor
  cmdline_str = path_str_to_inst_bin + " " +
                tmp;  // Replace argv[0] with instrumented PUT

  // Build options for PolyTracker executor
  cargv.emplace_back("/usr/bin/env");
  cargv.emplace_back("python3");
  cargv.emplace_back(path_str_to_executor.c_str());

  cargv.emplace_back("-c");
  cargv.emplace_back(cmdline_str.c_str());

  cargv.emplace_back("-i");  // XXX: Consider the stdin mode
  cargv.emplace_back(path_str_to_write_input.c_str());

  cargv.emplace_back("-d");
  cargv.emplace_back(path_str_to_db.c_str());

  cargv.emplace_back("-o");
  cargv.emplace_back(path_str_to_output.c_str());

  cargv.emplace_back(nullptr);
}
}  // namespace fuzzuf::executor
