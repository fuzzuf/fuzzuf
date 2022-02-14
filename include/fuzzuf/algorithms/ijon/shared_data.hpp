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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_SHARED_DATA_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_SHARED_DATA_HPP

#include "fuzzuf/algorithms/ijon/ijon_option.hpp"

namespace fuzzuf::algorithm::ijon {

/**
 * @struct SharedData
 * IJON has some extra fields in shared memory in addition to the array of edge coverage.
 * This struct represents its memory layout.
 */
struct SharedData {
    u8  afl_area[afl::option::GetMapSize<option::IJONTag>()];
    u64 afl_max[option::GetMaxMapSize<option::IJONTag>()];
    u8 is_selected;
};

} // namespace fuzzuf::algorithm::ijon

#endif
