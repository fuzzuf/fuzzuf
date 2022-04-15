/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#include "fuzzuf/algorithms/afl/afl_setting.hpp"
#include "fuzzuf/algorithms/mopt/mopt_option.hpp"

namespace fuzzuf::algorithm::mopt {

struct MOptSetting : public afl::AFLSetting {
    explicit MOptSetting(
        const std::vector<std::string> &argv,
        const std::string &in_dir,
        const std::string &out_dir,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        bool forksrv,
        bool dumb_mode,
        int cpuid_to_bind,
        const option::Schedule schedule
    );

    ~MOptSetting();

    u64 limit_time_puppet = 0; // should be configured through CLI
    u64 most_time_puppet = 0; // should be configured through CLI


    // limit_time_sig always set to 1 in original MOpt implementation
};

} // namespace fuzzuf::algorithm::mopt
