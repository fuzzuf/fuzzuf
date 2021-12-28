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
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/logger/logger.hpp"

// FIXME: this should be moved to Algorithms/AFL/?

void SetupDirs(std::string out_dir) {
    try {
        DEBUG("SetupDir\n");
        Util::CreateDir(out_dir);
        Util::CreateDir(out_dir + "/queue");
        Util::CreateDir(out_dir + "/queue/.state/");
        Util::CreateDir(out_dir + "/queue/.state/deterministic_done/");
        Util::CreateDir(out_dir + "/queue/.state/auto_extras/");
        Util::CreateDir(out_dir + "/queue/.state/redundant_edges/");
        Util::CreateDir(out_dir + "/queue/.state/variable_behavior/");
        Util::CreateDir(out_dir + "/crashes");
        Util::CreateDir(out_dir + "/hangs");
        
    } catch( const FileError &e) {
        std::cerr << e.what() << std::endl;
        throw;
    }
}
