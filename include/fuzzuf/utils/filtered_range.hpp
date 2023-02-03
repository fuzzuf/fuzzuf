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
 * @file filtered_range.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_FILTERED_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_FILTERED_RANGE_HPP
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <stdexcept>
#include <type_traits>

#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils::range {
/**
 * @class filtered_iterator
 * Iterator adaptor to traverse only values that specified callable returns true
 * The adaptor works as same as Boost.Iterator's filtered_iterator
 * https://www.boost.org/doc/libs/1_78_0/libs/iterator/doc/html/iterator/specialized/filter.html
 *
 * example:
 * std::vector< int > a{ ... };
 * b = a|filtered[ []( int v ) { return v < 10; } ];
 * b is a range that contains only lower than 10 values of a
 * The adaptor avoid need of temporary container to receive result of
 * std::copy_if
 */
template <typename T, typename U, typename Enable = void>
class filtered_iterator {};
#define FUZZUF_FILTERED_ITERATOR_BASIC_OPS                                   \
  using base_iter_t = T;                                                     \
  using difference_type = typename std::iterator_traits<T>::difference_type; \
  using value_type =                                                         \
      std::remove_reference_t<decltype(*std::declval<base_iter_t>())>;       \
  using pointer = void;                                                      \
  using reference = decltype(*std::declval<base_iter_t>());                  \
  filtered_iterator(const base_iter_t &p_, const base_iter_t &end_, U cond_) \
      : p(p_), end(end_), cond(cond_) {                                      \
    if (p != end) {                                                          \
      p = std::find_if(p, end, cond);                                        \
    }                                                                        \
  }                                                                          \
                                                                             \
  reference operator*() const {                                              \
    if (p == end) throw std::out_of_range("filtered_iterator::operator*()"); \
    return *p;                                                               \
  }                                                                          \
                                                                             \
  base_iter_t &get() { return p; }                                           \
  const base_iter_t &get() const { return p; }                               \
                                                                             \
  filtered_iterator &operator++() {                                          \
    if (p != end) {                                                          \
      ++p;                                                                   \
      p = std::find_if(p, end, cond);                                        \
    }                                                                        \
    return *this;                                                            \
  }                                                                          \
                                                                             \
  filtered_iterator operator++(int) {                                        \
    auto old = *this;                                                        \
    if (p != end) {                                                          \
      ++p;                                                                   \
      p = std::find_if(p, end, cond);                                        \
    }                                                                        \
    return old;                                                              \
  }

// requirements: T statisfies C++17 input iterator concept
template <typename T, typename U>
class filtered_iterator<T, U,
                        std::enable_if_t<std::is_same_v<
                            typename std::iterator_traits<T>::iterator_category,
                            std::input_iterator_tag>>> {
 public:
  using iterator_category = std::input_iterator_tag;
  FUZZUF_FILTERED_ITERATOR_BASIC_OPS
 private:
  base_iter_t p;
  base_iter_t end;
  U cond;
};
// requirements: T statisfies C++17 forward iterator concept
template <typename T, typename U>
class filtered_iterator<T, U,
                        std::enable_if_t<std::is_convertible_v<
                            typename std::iterator_traits<T>::iterator_category,
                            std::forward_iterator_tag>>> {
 public:
  using iterator_category = std::forward_iterator_tag;
  FUZZUF_FILTERED_ITERATOR_BASIC_OPS

  bool operator==(const filtered_iterator &r) const { return p == r.p; }

  bool operator!=(const filtered_iterator &r) const { return p != r.p; }

 private:
  base_iter_t p;
  base_iter_t end;
  U cond;
};

// requirements: T statisfies range concept
template <typename R, typename U>
auto make_filtered_range(R &v, U cond) -> std::enable_if_t<
    is_range_v<R>,
    boost::iterator_range<filtered_iterator<RangeIteratorT<R &>, U>>> {
  using iterator =
      std::remove_reference_t<decltype(std::declval<R &>().begin())>;
  return boost::make_iterator_range(
      filtered_iterator<iterator, U>(v.begin(), v.end(), cond),
      filtered_iterator<iterator, U>(v.end(), v.end(), cond));
}
template <typename R, typename U>
auto make_filtered_range(const R &v, U cond) -> std::enable_if_t<
    is_range_v<R>,
    boost::iterator_range<filtered_iterator<RangeIteratorT<const R &>, U>>> {
  using iterator =
      std::remove_reference_t<decltype(std::declval<const R &>().begin())>;
  return boost::make_iterator_range(
      filtered_iterator<iterator, U>(v.begin(), v.end(), cond),
      filtered_iterator<iterator, U>(v.end(), v.end(), cond));
}

namespace adaptor {
template <typename U>
struct filtered_t {
  U cond;
};
template <typename U>
filtered_t<U> filtered(U cond) {
  return filtered_t<U>{cond};
}

template <typename T, typename U>
auto operator|(T &p, const filtered_t<U> &cond)
    -> decltype(make_filtered_range(std::declval<T &>(), std::declval<U>())) {
  return make_filtered_range(p, cond.cond);
}
template <typename T, typename U>
auto operator|(const T &p, const filtered_t<U> &cond)
    -> decltype(make_filtered_range(std::declval<const T &>(),
                                    std::declval<U>())) {
  return make_filtered_range(p, cond.cond);
}

}  // namespace adaptor

}  // namespace fuzzuf::utils::range
#endif
