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
 * @file get_external_seeds.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_GET_EXTERNAL_SEEDS_HPP
#define FUZZUF_INCLUDE_UTILS_GET_EXTERNAL_SEEDS_HPP

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/mmap_range.hpp"
#include "fuzzuf/utils/shared_range.hpp"

namespace fuzzuf::utils {

range::mmap_range<range::shared_range<std::vector<fs::path>>> GetExternalSeeds(
    const fs::path &out_dir, const std::string &sync_id, bool update_synced);

}

#endif
