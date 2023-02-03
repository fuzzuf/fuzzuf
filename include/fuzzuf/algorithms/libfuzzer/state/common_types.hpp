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
 * @file common_types.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_COMMON_TYPES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_COMMON_TYPES_HPP
#include <cstdint>
#include <vector>

#include "fuzzuf/utils/map_file.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * A container type that is available to store coverage
 */
using coverage_t = std::vector<std::uint8_t>;
/**
 * A container type that is available to store standard output
 */
using output_t = std::vector<std::uint8_t>;

using output_files_t = std::vector<fuzzuf::utils::mapped_file_t>;

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
