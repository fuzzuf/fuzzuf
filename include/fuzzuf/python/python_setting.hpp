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

#include <string>
#include <vector>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::bindings::python {

struct PythonSetting {
  explicit PythonSetting(const std::vector<std::string> &argv,
                         const std::string &in_dir, const std::string &out_dir,
                         u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
                         bool need_afl_cov, bool need_bb_cov);

  ~PythonSetting();

  const std::vector<std::string> argv;
  const fs::path in_dir;
  const fs::path out_dir;
  const u32 exec_timelimit_ms;
  const u64 exec_memlimit;
  const bool forksrv;
  const bool need_afl_cov;
  const bool need_bb_cov;
};

}  // namespace fuzzuf::bindings::python
