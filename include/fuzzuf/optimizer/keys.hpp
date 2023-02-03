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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_KEYS_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_KEYS_HPP

#include <array>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::optimizer::keys {

namespace {
using AFLDictRef = utils::NullableRef<
    const std::vector<algorithm::afl::dictionary::AFLDictData>>;
using fuzzuf::mutator::NUM_CASE;
}  // namespace

const StoreKey<AFLDictRef> Extras{"extras"};
const StoreKey<AFLDictRef> AutoExtras{"aextras"};
const StoreKey<std::array<u32, fuzzuf::mutator::NUM_CASE>>
    SelectedCaseHistogram{"selected_case_histogram"};
const StoreKey<std::array<u64, NUM_CASE>> HavocOperatorFinds{
    "havoc_operator_finds"};
const StoreKey<u32> LastSpliceCycle{"last_splice_cycle"};
const StoreKey<u64> LastHavocFinds{"last_havoc_finds"};
const StoreKey<u32> LastHavocStacking{"last_havoc_stacking"};
const StoreKey<u32> SizeOfMutatedSeed{"size_of_mutated_seed"};
const StoreKey<std::vector<bool>> IsMutopBanned{"is_mutop_banned"};

}  // namespace fuzzuf::optimizer::keys

#endif
