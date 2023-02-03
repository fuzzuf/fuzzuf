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
 * @file crossover.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_CROSSOVER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_CROSSOVER_HPP
#include <cassert>
#include <iterator>
#include <type_traits>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/mutation/utils.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation_history.hpp"
#include "fuzzuf/algorithms/libfuzzer/random.hpp"
#include "fuzzuf/utils/range_traits.hpp"
namespace fuzzuf::algorithm::libfuzzer::mutator {

/**
 * Fetch random length chunks of values from data and crossover_with, then
 * output interleaved to the data. Or insert whole crossover_with into the
 * random position of data. Or copy random length of crossover_with int the
 * random position of data.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L422
 *
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @param max_size Max length of value
 * @return length of post modification value
 */
template <typename RNG, typename Range, typename Crossover_>
auto Crossover(RNG &rng, Range &data, size_t max_size, MutationHistory &history,
               const Crossover_ &crossover_with)
    -> std::enable_if_t<std::is_same_v<utils::range::RangeValueT<Range>,
                                       utils::range::RangeValueT<Crossover_>> &&
                            utils::range::has_data_v<Range> &&
                            utils::range::has_data_v<Crossover_> &&
                            utils::range::has_insert_range_v<Range>,
                        size_t> {
  const size_t size = utils::range::rangeSize(data);
  if (size > max_size) return 0u;
  if (size == 0u) return 0u;
  const size_t crossover_size = utils::range::rangeSize(crossover_with);
  if (crossover_size == 0u) return 0u;
  size_t new_size = 0u;
  using value_t = utils::range::RangeValueT<Range>;
  switch (random_value(rng, 3)) {
    case 0: {
      std::vector<value_t> mutate_in_place_here;
      mutate_in_place_here.reserve(max_size);
      new_size =
          detail::Crossover(rng, data, crossover_with,
                            std::back_inserter(mutate_in_place_here), max_size);
      utils::range::assign(mutate_in_place_here, data);
      break;
    }
    case 1: {
      if (!(new_size = detail::InsertPartOf(
                rng, crossover_with, data, crossover_with.data() == data.data(),
                max_size)))
        new_size = detail::CopyPartOf(rng, crossover_with, data,
                                      crossover_with.data() == data.data());
      break;
    }
    case 2: {
      new_size = detail::CopyPartOf(rng, crossover_with, data,
                                    crossover_with.data() == data.data());
      break;
    }
    default:
      assert(0);
  }
  assert(new_size > 0 && "CrossOver returned empty unit");
  assert(new_size <= max_size && "CrossOver returned overisized unit");
  static const char name[] = "CrossOver";
  history.push_back(MutationHistoryEntry{name});
  return utils::range::rangeSize(data);
}

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
