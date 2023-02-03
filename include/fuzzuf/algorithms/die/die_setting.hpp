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
 * @file die_setting.hpp
 * @brief Local option for DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/die/die_option.hpp"

namespace fuzzuf::algorithm::die {

struct DIESetting : public afl::AFLSetting {
 public:
  explicit DIESetting(const std::vector<std::string> &argv,
                      const std::string &in_dir, const std::string &out_dir,
                      u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
                      bool dumb_mode, int cpuid_to_bind,
                      const std::string &die_dir, const std::string &cmd_py,
                      const std::string &cmd_node, const std::string &d8_path,
                      const std::string &d8_flags,
                      const std::string &typer_path, int mut_cnt)
      : AFLSetting(argv, in_dir, out_dir, exec_timelimit_ms, exec_memlimit,
                   forksrv, dumb_mode, cpuid_to_bind),
        die_dir(die_dir),        // Path to DIE directory
        cmd_py(cmd_py),          // Command to execute Python 3
        cmd_node(cmd_node),      // Command to execute JavaScript
        d8_path(d8_path),        // Path to V8 engine
        d8_flags(d8_flags),      // Flags passed to V8 engine
        typer_path(typer_path),  // Path to typer script
        mut_cnt(mut_cnt)         // Number of scripts to generate per mutation
  {}
  ~DIESetting() {}

  const std::string die_dir;
  const std::string cmd_py;
  const std::string cmd_node;
  const std::string d8_path;
  const std::string d8_flags;
  const std::string typer_path;
  int mut_cnt;
};

}  // namespace fuzzuf::algorithm::die
