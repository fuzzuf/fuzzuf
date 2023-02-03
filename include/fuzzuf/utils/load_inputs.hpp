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
 * @file load_inputs.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_LOAD_INPUTS_HPP
#define FUZZUF_INCLUDE_UTILS_LOAD_INPUTS_HPP

#include <vector>

#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"

namespace fuzzuf::utils {
/**
 * Mmap all files under the directory and return mmaped ranges.
 * Subdirectories under the specified directory are traversed recursively.
 * @param dir Directory to find files.
 * @param check_sha1 Calcurate Sha1 for each file contents and ignore file which
 * name doesn't match to the hash.
 * @return vector of mmaped ranges
 */
auto LoadInputs(const fs::path &dir, bool check_sha1)
    -> std::vector<utils::mapped_file_t>;
}  // namespace fuzzuf::utils

#endif
