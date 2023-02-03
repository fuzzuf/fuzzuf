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
 * @file dictionary.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_DICTIONARY_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_DICTIONARY_HPP
#include <cassert>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/mutation/utils.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Retrive a word from the dictionary and insert at the random position of data.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L160
 * and
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L280
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @tparam Dict Type of dictionary
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @param dict_entry History of selected words
 * @param dict Dictinary
 * @return length of post modification value
 */
template <typename RNG, typename Range, typename Dict>
auto Dictionary(RNG &rng, Range &data, std::size_t max_size,
                MutationHistory &history,
                std::vector<utils::range::RangeValueT<Dict> *> &dict_entry,
                Dict &dict)
    -> std::enable_if_t<
        // Rangeは辞書の単語の要素の型を要素の型とするrangeである
        utils::range::is_range_of_v<
            Range, utils::range::RangeValueT<dictionary::WordTypeT<Dict>>>,
        std::size_t> {
  static const char name[] = "Dict";
  history.push_back(MutationHistoryEntry{name});
  return detail::AddWordFromDictionary(rng, dict, data, max_size, dict_entry);
}

/**
 * Append selected words history to specified dictionary
 * This operation is needed to update persistent auto dict.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L458
 *
 * @tparam Dict Type of dictionary
 * @param dict Dictionary to update
 * @param dict_entry History of selected words
 */
template <typename Dict>
void UpdateDictionary(
    Dict &dict, std::vector<utils::range::RangeValueT<Dict> *> &dict_entries) {
  std::vector<utils::range::RangeValueT<Dict>> copied_dict_entries;
  copied_dict_entries.reserve(dict_entries.size());
  std::transform(dict_entries.begin(), dict_entries.end(),
                 std::back_inserter(copied_dict_entries), [](const auto &p) {
                   // PersistentAutoDictionary.AddWithSuccessCountOne(DE);
                   p->increment_success_count();
                   assert(p->get().size());
                   return *p;
                 });
  for (auto &dict_entry : copied_dict_entries) {
    const auto &new_word = dict_entry.get();
    if (std::find_if(dict.begin(), dict.end(), [&](auto &v) {
          if (dict_entry.get_hash() != v.get_hash()) return false;
          const auto &existing_word = v.get();
          // Linear search is fine here as this happens seldom.
          return std::equal(existing_word.begin(), existing_word.end(),
                            new_word.begin(), new_word.end());
        }) == dict.end()) {
      dict_entry.reset_use_count();
      utils::range::append(dict_entry, dict);
    }
  }
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
