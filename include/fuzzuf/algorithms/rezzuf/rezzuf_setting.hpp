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

#ifndef FUZZUF_INCLUDE_ALGORITHM_REZZUF_REZZUF_SETTING_HPP
#define FUZZUF_INCLUDE_ALGORITHM_REZZUF_REZZUF_SETTING_HPP

#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_setting.hpp"

namespace fuzzuf::algorithm::rezzuf {

struct RezzufSetting : public afl::AFLSetting {
  explicit RezzufSetting(const std::vector<std::string>& argv,
                         const std::string& in_dir, const std::string& out_dir,
                         u32 exec_timelimit_ms, u64 exec_memlimit, bool forksrv,
                         bool dumb_mode, int cpuid_to_bind,
                         const aflfast::option::Schedule schedule,
                         const std::string& schedule_string);

  ~RezzufSetting();

  const aflfast::option::Schedule schedule = aflfast::option::FAST;
  std::string schedule_string = "fast";
};

}  // namespace fuzzuf::algorithm::rezzuf

#endif
