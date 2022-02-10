/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file setting.hpp
 * @brief Setting of nautilus
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <optional>
#include <string>
#include <vector>
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer {

struct NautilusSetting {
  const std::vector<std::string>& argv;
  u32  exec_timelimit_ms;
  u64  exec_memlimit;
  bool forksrv;
  u32  afl_shm_size;
  u32  bb_shm_size;
  int  cpuid_to_bind;
  u16  number_of_generate_inputs;
  u64  number_of_deterministic_mutations;
  u64  max_tree_size;
  u64  bitmap_size;
  const fs::path path_to_grammar;
  const fs::path path_to_workdir;
  bool hide_output;
};

} // namespace fuzzuf::algorithm::nautilus::fuzzer
