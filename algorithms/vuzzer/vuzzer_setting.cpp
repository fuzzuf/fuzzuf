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
#include "fuzzuf/algorithms/vuzzer/vuzzer_setting.hpp"

#include <optional>
#include <string>
#include <vector>

namespace fuzzuf::algorithm::vuzzer {

VUzzerSetting::VUzzerSetting(
    const std::vector<std::string> &argv, const std::string &in_dir,
    const std::string &out_dir, const std::string &weight_file,
    const std::string &full_dict, const std::string &unique_dict,
    const std::string &inst_bin, const std::string &taint_db,
    const std::string &taint_file, u32 exec_timelimit_ms, u64 exec_memlimit)
    : argv(argv),
      in_dir(in_dir),
      out_dir(out_dir),
      path_to_weight_file(weight_file),
      path_to_full_dict(full_dict),
      path_to_unique_dict(unique_dict),
      path_to_inst_bin(inst_bin),
      path_to_taint_db(taint_db),
      path_to_taint_file(taint_file),
      exec_timelimit_ms(exec_timelimit_ms),
      exec_memlimit(exec_memlimit) {}

VUzzerSetting::~VUzzerSetting() {}

}  // namespace fuzzuf::algorithm::vuzzer
