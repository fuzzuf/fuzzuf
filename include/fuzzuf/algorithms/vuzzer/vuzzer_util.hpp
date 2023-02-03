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

#include <boost/dynamic_bitset.hpp>
#include <string>

#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_testcase.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::vuzzer::util {

void ParseBBWeights(VUzzerState& state, const fs::path& path);

void ParseBBCov(feedback::FileFeedback& inp_feed, std::map<u64, u32>& bb_cov);

void ParseTaintInfo(VUzzerState& state,
                    const std::shared_ptr<VUzzerTestcase>& testcase,
                    feedback::FileFeedback& inp_feed);

void DictToBitsWithKeys(std::map<u64, u32>& dict, std::vector<u64>& keys,
                        boost::dynamic_bitset<>& bits);

std::unique_ptr<std::vector<u8>> GenerateRandomBytesFromDict(
    u32 size, const std::vector<const dict_t*>& all_dicts);

}  // namespace fuzzuf::algorithm::vuzzer::util
