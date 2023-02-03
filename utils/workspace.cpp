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
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::utils {
// FIXME: this should be moved to Algorithms/AFL/?

void SetupDirs(std::string out_dir) {
  try {
    DEBUG("SetupDir\n");
    fs::create_directories(out_dir);
    fs::create_directories(out_dir + "/queue");
    fs::create_directories(out_dir + "/queue/.state/");
    fs::create_directories(out_dir + "/queue/.state/deterministic_done/");
    fs::create_directories(out_dir + "/queue/.state/auto_extras/");
    fs::create_directories(out_dir + "/queue/.state/redundant_edges/");
    fs::create_directories(out_dir + "/queue/.state/variable_behavior/");
    fs::create_directories(out_dir + "/crashes");
    fs::create_directories(out_dir + "/hangs");

  } catch (const FileError &e) {
    std::cerr << e.what() << std::endl;
    throw;
  }
}
}  // namespace fuzzuf::utils
