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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_HAVOC_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_HAVOC_HPP

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"

namespace fuzzuf::algorithm::ijon::havoc {

u32 IJONHavocCaseDistrib(
    const std::vector<afl::dictionary::AFLDictData>& extras,
    const std::vector<afl::dictionary::AFLDictData>& a_extras
);

void IJONCustomCases(
    u32 case_idx,
    u8*& outbuf,
    u32& len,
    const std::vector<afl::dictionary::AFLDictData>& extras,
    const std::vector<afl::dictionary::AFLDictData>& a_extras
);

} // namespace fuzzuf::algorithm::ijon::havoc

#endif
