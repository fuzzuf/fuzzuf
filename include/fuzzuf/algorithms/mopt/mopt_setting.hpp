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

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_SETTING_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_SETTING_HPP

#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"

namespace fuzzuf::algorithm::mopt {

struct MOptSetting : public afl::AFLSetting {
  explicit MOptSetting(const std::vector<std::string> &argv,
                       const std::string &in_dir, const std::string &out_dir,
                       u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
                       bool dumb_mode, int cpuid_to_bind, u64 mopt_limit_time,
                       u64 mopt_most_time);

  ~MOptSetting();

  u64 mopt_limit_time = 1;  // limit_time_puppet
  u64 mopt_most_time = 0;   // most_time_puppet

  // limit_time_sig always set to 1 in original MOpt implementation
};

}  // namespace fuzzuf::algorithm::mopt

#endif
