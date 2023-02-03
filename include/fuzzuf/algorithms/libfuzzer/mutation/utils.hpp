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
 * @file utils.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_UTILS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_UTILS_HPP
#include <type_traits>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"
#include "fuzzuf/algorithms/libfuzzer/state_traits.hpp"
#include "fuzzuf/utils/bswap.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::algorithm::libfuzzer::mutator {

template <typename T>
using RemoveCvrT = utils::type_traits::RemoveCvrT<T>;

template <typename T>
using bswap = utils::bswap<T>;

template <typename E>
auto IncrementUseCount(E &e) -> std::enable_if_t<has_IncrementUseCount1_v<E>> {
  e.increment_use_count();
}

template <typename E>
auto IncrementUseCount(E &e) -> std::enable_if_t<!has_IncrementUseCount1_v<E> &&
                                                 has_IncrementUseCount2_v<E>> {
  e.increment_use_count();
}

template <typename E>
auto IncrementUseCount(const E &)
    -> std::enable_if_t<!has_IncrementUseCount1_v<E> &&
                        !has_IncrementUseCount2_v<E>> {}

template <typename E>
auto get_word(E &e)
    -> std::enable_if_t<has_IncrementUseCount1_v<E> && has_get_word1_v<E>,
                        decltype(std::declval<E &>().get())> {
  return e.get();
}

template <typename E>
auto get_word(E &e)
    -> std::enable_if_t<!(has_IncrementUseCount1_v<E> &&
                          has_get_word1_v<E>)&&has_IncrementUseCount2_v<E> &&
                            has_get_word2_v<E>,
                        decltype(std::declval<E &>().getW())> {
  return e.GetW();
}

template <typename E>
auto get_word(const E &e)
    -> std::enable_if_t<!(has_IncrementUseCount1_v<E> && has_get_word1_v<E>)&&!(
                            has_IncrementUseCount2_v<E> && has_get_word2_v<E>),
                        E &> {
  return e;
}

template <typename E>
auto has_position_hint(E &e)
    -> std::enable_if_t<has_has_position_hint1_v<E>, bool> {
  return e.has_position_hint();
}

template <typename E>
auto has_position_hint(E &e) -> std::enable_if_t<
    !has_has_position_hint1_v<E> && has_has_position_hint2_v<E>, bool> {
  return e.HasPositionHint();
}

template <typename E>
auto has_position_hint(const E &) -> std::enable_if_t<
    !has_GetPositionHint1_v<E> && !has_GetPositionHint2_v<E>, bool> {
  return false;
}

template <typename E>
auto GetPositionHint(E &e)
    -> std::enable_if_t<has_GetPositionHint1_v<E>, std::size_t> {
  return e.get_position_hint();
}

template <typename E>
auto GetPositionHint(E &e) -> std::enable_if_t<
    !has_has_position_hint1_v<E> && has_GetPositionHint2_v<E>, std::size_t> {
  return e.GetPositionHint();
}

template <typename E>
auto GetPositionHint(const E &) -> std::enable_if_t<
    !has_has_position_hint1_v<E> && !has_GetPositionHint2_v<E>, std::size_t> {
  return 0u;
}

namespace detail {

/**
 * Copy [begin1, end1) to [begin2, end2).
 * If both range size is not same, elements in shorter range size are affected.
 * It is acceptable to overwrap both ranges.
 *
 * @tparam Iterator Source iterator. forward_iterator or higher is required.
 * @tparam OutputIterator Destination iterator. forward_iterator or higher is
 * required.
 * @param begin1 Begin of source
 * @param end1 End of source
 * @param begin2 Begin of destination
 * @param end2 End of destination
 */
template <typename Iterator, typename OutputIterator>
void CopySelf(Iterator begin1, Iterator end1, OutputIterator begin2,
              OutputIterator end2) {
  if (end1 < begin1) std::swap(begin1, end1);
  if (end2 < begin2) std::swap(begin2, end2);
  const auto from_size = std::distance(begin1, end1);
  const auto to_size = std::distance(begin2, end2);
  if (from_size < to_size)
    end2 = std::next(begin2, from_size);
  else if (to_size < from_size)
    end1 = std::next(begin1, to_size);
  if (begin2 == end2) return;
  if (begin1 == begin2)
    return;
  else if (end1 <= begin2 || end2 <= begin1 || (begin2 < begin1))
    std::copy(begin1, end1, begin2);
  else
    std::copy_backward(begin1, end1, end2);
}

/*
 * Insert [begin, end) to specified position.
 * The inserting position is permitted to be placed between begin and end.
 *
 * @tparam Iterator Source iterator. forward_iterator or higher is required.
 * @tparam OutputIterator Inserting position iterator. output_iterator or higher
 * is required.
 * @param begin1begin Of source
 * @param end End of source
 * @param at Inserting position
 */
template <typename Iterator, typename OutputIterator>
void InsertSelf(Iterator begin, Iterator end, OutputIterator at) {
  if (end < begin) std::swap(begin, end);
  if (begin == end) return;
  using value_type =
      RemoveCvrT<typename std::iterator_traits<Iterator>::value_type>;
  if (std::distance(begin, end) < 200u) {
    std::array<value_type, 200u> temp;
    std::copy(begin, end, temp.begin());
    std::copy(temp.begin(), std::next(temp.begin(), std::distance(begin, end)),
              at);
  } else {
    std::vector<value_type> temp(begin, end);
    std::copy(temp.begin(), temp.end(), at);
  }
}

/*
 * Copy random length of "from" from random offset to random length of "to" from
 * random offset.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L299
 *
 * @tparam RNG Type of random number generator
 * @tparam R1 "from" range type
 * @tparam R2 "to" range type
 * @param rng Random number generator
 * @param from The range to copy values from
 * @param to The range to copy values to
 * @param potential_overlap Set true if "from" and "to" can overwrap. Otherwise,
 * set false.
 * @return length of "to"
 */
template <typename RNG, typename R1, typename R2>
auto CopyPartOf(RNG &rng, const R1 &from, R2 &to, bool potential_overlap)
    -> std::enable_if_t<utils::range::is_range_of_v<R1, std::uint8_t> &&
                            utils::range::is_range_of_v<R2, std::uint8_t> &&
                            utils::range::has_insert_range_v<R2>,
                        std::size_t> {
  const std::size_t from_size = utils::range::rangeSize(from);
  const std::size_t to_size = utils::range::rangeSize(to);
  const std::size_t to_beg = random_value(rng, to_size);
  std::size_t copy_size = random_value(rng, to_size - to_beg) + 1;
  assert(to_beg + copy_size <= to_size);
  copy_size = std::min(copy_size, from_size);
  const std::size_t from_beg = random_value(rng, from_size - copy_size + 1);
  assert(from_beg + copy_size <= from_size);
  if (potential_overlap) {
    CopySelf(std::next(from.begin(), from_beg),
             std::next(from.begin(), from_beg + copy_size),
             std::next(to.begin(), to_beg),
             std::next(to.begin(), to_beg + copy_size));
  } else {
    std::copy(std::next(from.begin(), from_beg),
              std::next(from.begin(), from_beg + copy_size),
              std::next(to.begin(), to_beg));
  }
  return to_size;
}

/*
 * Fetch random length chunks of values from r1 and r2, then output interleaved
 * to the dest.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCrossOver.cpp#L19
 *
 * @tparam RNG Type of random number generator
 * @tparam R1 First source range type
 * @tparam R2 Second source range type
 * @tparam OutputIterator Output_iterator or higher
 * @param rng Random number generator
 * @param r1 First source range
 * @param r2 Second source range
 * @param dest An output iterator to write interleaved values.
 * @return total copied size
 */
template <typename RNG, typename R1, typename R2, typename OutputIterator>
auto Crossover(RNG &rng, const R1 &r1, const R2 &r2, OutputIterator dest,
               std::size_t max_size)
    -> std::enable_if_t<utils::range::is_range_of_v<R1, std::uint8_t> &&
                            utils::range::is_range_of_v<R2, std::uint8_t>,
                        std::size_t> {
  auto size1 = utils::range::rangeSize(r1);
  auto size2 = utils::range::rangeSize(r2);
  assert(size1 || size2);
  max_size = random_value(rng, max_size) + 1u;
  auto i1 = r1.begin();
  auto i2 = r2.begin();
  std::size_t count = 0u;
  while ((i1 != r1.end() || i2 != r2.end()) && count != max_size) {
    if (i1 != r1.end() && count != max_size) {
      auto max_extra_size = std::min(std::size_t(max_size - count),
                                     std::size_t(std::distance(i1, r1.end())));
      auto extra_size = random_value(rng, max_extra_size) + 1u;
      auto end = std::next(i1, extra_size);
      dest = std::copy(i1, end, dest);
      i1 = end;
      count += extra_size;
    }
    if (i2 != r2.end() && count != max_size) {
      auto max_extra_size = std::min(std::size_t(max_size - count),
                                     std::size_t(std::distance(i2, r2.end())));
      auto extra_size = random_value(rng, max_extra_size) + 1u;
      auto end = std::next(i2, extra_size);
      dest = std::copy(i2, end, dest);
      i2 = end;
      count += extra_size;
    }
  }
  return count;
}

/*
 * Insert or copy specified dictionary entry at the random position of data.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L166
 *
 * @tparam RNG Type of random number generator
 * @tparam R Destination container type
 * @tparam E Dictionary entry type
 * @param rng Random number generator
 * @param data Destination to write dictionary entry
 * @param dict_entry Dictionary entry
 * @param max_size Max length of data
 * @return length of post modification data
 */
template <typename RNG, typename R, typename E>
auto ApplyDictionaryEntry(RNG &rng, R &data, E &dict_entry,
                          std::size_t max_size)
    -> std::enable_if_t<
        utils::range::is_range_of_v<R, std::uint8_t> &&
            utils::range::is_range_of_v<
                RemoveCvrT<decltype(get_word(std::declval<E &>()))>,
                std::uint8_t> &&
            utils::range::has_insert_range_v<R>,
        std::size_t> {
  const std::size_t size = utils::range::rangeSize(data);
  const auto &word = get_word(dict_entry);
  const bool use_position_hint =
      has_position_hint(dict_entry) &&
      GetPositionHint(dict_entry) + utils::range::rangeSize(word) < size &&
      random_value<bool>(rng);
  if (random_value<bool>(rng)) {
    if (size + utils::range::rangeSize(word) > max_size) return 0u;
    const std::size_t index = use_position_hint ? GetPositionHint(dict_entry)
                                                : random_value(rng, size + 1);
    data.insert(std::next(data.begin(), index), word.begin(), word.end());
  } else {
    if (utils::range::rangeSize(word) > size) return 0u;
    const std::size_t index =
        use_position_hint
            ? GetPositionHint(dict_entry)
            : random_value(rng, size + 1 - utils::range::rangeSize(word));
    std::copy(word.begin(), word.end(), std::next(data.begin(), index));
  }
  return utils::range::rangeSize(data);
}

/*
 * Insert or copy randomly selected dictionary entry at the random position of
 * data.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L285
 *
 * @tparam RNG Type of random number generator
 * @tparam Dict Dictionary type
 * @tparam R Destination container type
 * @param rng Random number generator
 * @param dict Dictionary
 * @param data Destination to write dictionary entry
 * @param max_size Max length of data
 * @return length of post modification data
 */
template <typename RNG, typename Dict, typename R>
auto AddWordFromDictionary(
    RNG &rng, Dict &dict, R &data, std::size_t max_size,
    std::vector<utils::range::RangeValueT<Dict> *> &dict_entry_)
    -> std::enable_if_t<
        utils::range::is_range_of_v<
            R, utils::range::RangeValueT<dictionary::WordTypeT<Dict>>>,
        std::size_t> {
  const std::size_t size = utils::range::rangeSize(data);
  if (size > max_size) return 0u;
  if (utils::range::rangeEmpty(dict)) {
    return 0u;
  }
  const std::size_t dict_size = utils::range::rangeSize(dict);
  auto &dict_entry = *std::next(dict.begin(), random_value(rng, dict_size));
  const std::size_t final_size =
      ApplyDictionaryEntry(rng, data, dict_entry, max_size);
  if (!final_size) return 0u;
  IncrementUseCount(dict_entry);
  dict_entry_.push_back(&dict_entry);
  return final_size;
}

/*
 * Insert random length of "from" from random offset to random position of "to".
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L314
 *
 * @tparam RNG Type of random number generator
 * @tparam R1 "from" range type
 * @tparam R2 "to" range type
 * @param rng Random number generator
 * @param from The range to insert values from
 * @param to The range insert values to
 * @param potential_overlap Set true if "from" and "to" can overwrap. Otherwise,
 * set false.
 * @return length of post modified "to"
 */
template <typename RNG, typename R1, typename R2>
auto InsertPartOf(RNG &rng, const R1 &from, R2 &to, bool potential_overlap,
                  std::size_t max_size)
    -> std::enable_if_t<utils::range::is_range_of_v<R1, std::uint8_t> &&
                            utils::range::is_range_of_v<R2, std::uint8_t> &&
                            utils::range::has_insert_range_v<R2>,
                        std::size_t> {
  const std::size_t from_size = utils::range::rangeSize(from);
  const std::size_t to_size = utils::range::rangeSize(to);
  const std::size_t max_to_size = max_size;
  if (to_size >= max_to_size) return 0u;
  const std::size_t available_space = max_to_size - to_size;
  const std::size_t max_copy_size = std::min(available_space, from_size);
  const std::size_t copy_size = random_value(rng, max_copy_size) + 1;
  const std::size_t from_beg = random_value(rng, from_size - copy_size + 1);
  assert(from_beg + copy_size <= from_size);
  const std::size_t to_insert_pos = random_value(rng, to_size + 1);
  assert(to_insert_pos + copy_size <= max_to_size);
  if (potential_overlap) {
    detail::InsertSelf(std::next(from.begin(), from_beg),
                       std::next(from.begin(), from_beg + copy_size),
                       std::inserter(to, std::next(to.begin(), to_insert_pos)));
  } else {
    to.insert(std::next(to.begin(), to_insert_pos),
              std::next(from.begin(), from_beg),
              std::next(from.begin(), from_beg + copy_size));
  }
  return to_size + copy_size;
}

/*
 * Insert random length of "from" from random offset to random position of "to".
 * Consider sizeof(T) bytes at random offset of data is a value of integer type
 * T, then modify the value in range of -10 to 10 and writeback modified value
 * to original position.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L384
 *
 * @tparam T Integer type
 * @tparam RNG Type of random number generator
 * @tparam Range Container of the value
 * @param rng Random number generator
 * @param data Value to modify
 * @return length of post modification value
 */
template <typename T, typename RNG, typename Range>
auto ChangeBinaryInteger(RNG &rng, Range &data)
    -> std::enable_if_t<utils::range::is_range_of_v<Range, std::uint8_t>,
                        std::size_t> {
  const std::size_t size = utils::range::rangeSize(data);
  if (size < sizeof(T)) return 0u;
  const std::size_t offset = random_value(rng, size - sizeof(T) + 1);
  assert(offset + sizeof(T) <= size);
  T value;
  if (offset < 64u && !random_value(rng, 3u)) {
    value = static_cast<T>(size);
    if (random_value<bool>(rng)) value = bswap<T>()(value);
  } else {
    std::copy(std::next(data.begin(), offset),
              std::next(data.begin(), offset + sizeof(T)),
              reinterpret_cast<std::uint8_t *>(&value));
    T add = static_cast<T>(random_value(rng, 21u));
    add -= 10u;
    if (random_value<bool>(rng))
      value = bswap<T>()(T(bswap<T>()(value) + add));
    else
      value = value + add;
    if (add == 0 || random_value<bool>(rng)) value = -value;
  }
  std::copy(reinterpret_cast<std::uint8_t *>(&value),
            std::next(reinterpret_cast<std::uint8_t *>(&value), sizeof(T)),
            std::next(data.begin(), offset));
  return utils::range::rangeSize(data);
}

}  // namespace detail

}  // namespace fuzzuf::algorithm::libfuzzer::mutator
#endif
