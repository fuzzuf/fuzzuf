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
 * @file zip_range.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_ZIP_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_ZIP_RANGE_HPP
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <type_traits>

#include "fuzzuf/utils/minimum_iterator_category.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils::range {

/**
 * @class zip_iterator
 * @brief
 * Iterator adaptor that combine multiple iterators and return an iterator that
 * std::get is available for the dereferenced value
 * @tparam T Type of iterators
 *
 * example:
 * std::vector< int > a{ ... };
 * std::vector< float > b{ ... };
 * c = zip( a, b );
 * c is a range with iterator that returns std::tuple< int&, float& > that
 * refers each element from a and b
 */
template <typename... T>
class zip_iterator {
 public:
  using iterator_category = minimum_iterator_category_t<
      std::tuple<std::forward_iterator_tag,
                 typename std::iterator_traits<T>::iterator_category...>>;
  using base_iter_t = std::tuple<T...>;
  using difference_type = std::ptrdiff_t;
  using value_type = std::tuple<
      utils::type_traits::RemoveCvrT<decltype(*std::declval<T>())>...>;
  using pointer = void;
  using reference = std::tuple<decltype(*std::declval<T>())...>;
  zip_iterator(T... p_) : p(p_...) {}
  reference operator*() const {
    return dereference<0u, std::tuple_size_v<base_iter_t>>();
  }

  base_iter_t &get() { return p; }
  const base_iter_t &get() const { return p; }

  zip_iterator &operator++() {
    increment<0u, std::tuple_size_v<base_iter_t>>();
    return *this;
  }

  zip_iterator operator++(int) {
    auto old = *this;
    increment<0u, std::tuple_size_v<base_iter_t>>();
    return old;
  }

  bool operator==(const zip_iterator &r) const { return p == r.p; }

  bool operator!=(const zip_iterator &r) const { return p != r.p; }

 private:
  template <size_t begin, size_t end>
  auto dereference(std::enable_if_t<(begin == end)> * = 0) const {
    return std::tuple<>();
  }
  template <size_t begin, size_t end>
  auto dereference(std::enable_if_t<(begin < end)> * = 0) const {
    return std::tuple_cat(
        std::tuple<decltype(*std::get<begin>(p))>(*std::get<begin>(p)),
        dereference<begin + 1u, end>());
  }
  template <size_t begin, size_t end>
  void increment(std::enable_if_t<(begin == end)> * = 0) {}
  template <size_t begin, size_t end>
  auto increment(std::enable_if_t<(begin < end)> * = 0) {
    ++std::get<begin>(p);
    increment<begin + 1u, end>();
  }
  base_iter_t p;
};

/**
 * Return shortest range size in the ranges in arguments
 * If no ranges are passed, return value is std::numeric_limits< size_t >::max()
 */
auto minimum_rangeSize() -> std::size_t;

template <typename Head, typename... Tail>
auto minimum_rangeSize(const Head &head, const Tail &...tail) -> std::size_t {
  return std::min(rangeSize(head), minimum_rangeSize(tail...));
}

/**
 * Create zip range
 * Combine multiple range into a range with zip_iterator as the iterator
 * @tparam R Type of ranges
 * @param v Ranges
 */
template <typename... R>
auto zip(R &...v) {
  const auto size = minimum_rangeSize(v...);
  return boost::make_iterator_range(
      zip_iterator<
          std::remove_reference_t<decltype(std::declval<R>().begin())>...>(
          v.begin()...),
      zip_iterator<
          std::remove_reference_t<decltype(std::declval<R>().begin())>...>(
          std::next(v.begin(), size)...));
}
template <typename... R>
auto zip(const R &...v) {
  const auto size = minimum_rangeSize(v...);
  return boost::make_iterator_range(
      zip_iterator<utils::type_traits::RemoveCvrT<
          decltype(std::declval<const R>().begin())>...>(v.begin()...),
      zip_iterator<utils::type_traits::RemoveCvrT<
          decltype(std::declval<const R>().begin())>...>(
          std::next(v.begin(), size)...));
}

}  // namespace fuzzuf::utils::range

#endif
