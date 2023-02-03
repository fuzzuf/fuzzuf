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

#include <optional>
#include <string>
#include <vector>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::vuzzer {

struct VUzzerSetting {
  explicit VUzzerSetting(
      const std::vector<std::string> &argv, const std::string &in_dir,
      const std::string &out_dir, const std::string &weight_file,
      const std::string &full_dict, const std::string &unique_dict,
      const std::string &inst_bin, const std::string &taint_db,
      const std::string &taint_file, u32 exec_timelimit_ms, u64 exec_memlimit);

  ~VUzzerSetting();

  const std::vector<std::string> argv;
  const fs::path in_dir;
  const fs::path out_dir;

  const fs::path path_to_weight_file;
  const fs::path path_to_full_dict;
  const fs::path path_to_unique_dict;

  const fs::path path_to_inst_bin;
  const fs::path path_to_taint_db;
  const fs::path path_to_taint_file;

  const u32 exec_timelimit_ms;
  const u64 exec_memlimit;
  const bool simple_files = false;
  const bool ignore_finds = false;

  /* TODO: Move to VUzzerOption */
  const u32 ehb_bb_ratio = 90;
  const double ehb_fitness_ratio = 0.5;
  const u32 bb_cnt_max = 10000;
  const u32 bb_weight_max = 65536;
  const u32 input_len_max = 50000;
  const u32 pop_size = 500;  // TODO: Fuckin rename
  const u32 next_gen_range =
      40;  // Number of best inputs to go in the next generation. Make sure that
           // pop_size-next_gen_range is multiple of 2.
  const u32 next_gen_from_special_prob =
      3;  // Set probability of selecting new inputs from special or best
          // inputs. Higer the number (0-9), less will be the chance of
          // selecting from Special inputs.
  const double mutate_after_crossover_prob = 0.9;
  const double fill_seeds_with_crossover_prob = 0.3;
  const u32 keep_num_of_seed_queue =
      40;  // for elitist approach, set number of best inputs to go in the next
           // generation. Make sure that pop_size - keep_num_of_seed_queue is
           // multiple of 2.
};

}  // namespace fuzzuf::algorithm::vuzzer
