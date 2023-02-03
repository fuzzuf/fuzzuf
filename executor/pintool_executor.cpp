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
#include "fuzzuf/executor/pintool_executor.hpp"

#include "fuzzuf/utils/check_crash_handling.hpp"

namespace fuzzuf::executor {
PinToolExecutor::PinToolExecutor(const fs::path &proxy_path,
                                 const std::vector<std::string> &pargv,
                                 const std::vector<std::string> &argv,
                                 u32 exec_timelimit_ms, u64 exec_memlimit,
                                 const fs::path &path_to_write_input)
    : BaseProxyExecutor(proxy_path, pargv, argv, exec_timelimit_ms,
                        exec_memlimit, path_to_write_input) {
  fuzzuf::utils::CheckCrashHandling();

  SetCArgvAndDecideInputMode();
  BaseProxyExecutor::Initilize();
}

void PinToolExecutor::SetCArgvAndDecideInputMode() {
  assert(!argv.empty());

  stdin_mode = true;  // if we find @@, then assign false to stdin_mode

  cargv.emplace_back(proxy_path.c_str());
  cargv.emplace_back("-t");

  for (const auto &v : pargv) {
    cargv.emplace_back(v.c_str());
  }

  cargv.emplace_back("--");

  for (const auto &v : argv) {
    if (v == "@@") {
      stdin_mode = false;
      cargv.emplace_back(path_str_to_write_input.c_str());
    } else {
      cargv.emplace_back(v.c_str());
    }
  }
  cargv.emplace_back(nullptr);
}
}  // namespace fuzzuf::executor
