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

#ifndef FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_OPTION_GET_SPLICE_CYCLES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_MOPT_MOPT_OPTION_GET_SPLICE_CYCLES_HPP

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"

// separated from mopt_option.hpp as methods defined here use MOptState member

namespace fuzzuf::algorithm::afl::option {

template <>
u32 GetSpliceCycles<mopt::MOptState>(mopt::MOptState& state) {
  return state.splice_cycles_limit;
}

}  // namespace fuzzuf::algorithm::afl::option

#endif
