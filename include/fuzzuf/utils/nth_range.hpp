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
 * @file nth_range.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_NTH_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_NTH_RANGE_HPP
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <type_traits>

#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils::range {

/**
 * @class nth_iterator
 * @brief An Iterator adaptor to extract i-th element of std::get-able value
 * @tparam T Base iterator type
 * @tparam i Return i-th value
 *
 * example:
 * std::vector< std::tuple< int, int, int > > a{ ... };
 * b = a|nth< 2 >;
 * b is a range that extract only second tuple element of each a elements.
 * This is useful to avoid creating temporary vector that contains only second
 * tuple elements.
 *
 * This adapter perform like map_keys and map_values in Boost.Range.
 * Beside map_keys and map_values support std::pair only, this adapter support
 * any types that elements can be extracted by std::get. (In other word, this
 * adaptor works on tuple too)
 * https://www.boost.org/doc/libs/1_52_0/libs/range/doc/html/range/reference/adaptors/reference/map_keys.html
 * https://www.boost.org/doc/libs/1_52_0/libs/range/doc/html/range/reference/adaptors/reference/map_values.html
 */
template <typename T, std::size_t i, typename Enable = void>
class nth_iterator {};

#define FUZZUF_NTH_ITERATOR_BASIC_OPS                                        \
  using base_iter_t = T;                                                     \
  using difference_type = typename std::iterator_traits<T>::difference_type; \
  using value_type =                                                         \
      std::remove_reference_t<decltype(std::get<i>(*std::declval<T>()))>;    \
  using pointer = void;                                                      \
  using reference = value_type &;                                            \
  nth_iterator(const T &base_) : base(base_) {}                              \
  reference operator*() const { return std::get<i>(*base); }                 \
  T &get() { return base; }                                                  \
  const T &get() const { return base; }                                      \
  nth_iterator &operator++() {                                               \
    ++get();                                                                 \
    return *this;                                                            \
  }                                                                          \
  nth_iterator operator++(int) {                                             \
    auto old = *this;                                                        \
    get()++;                                                                 \
    return old;                                                              \
  }

template <typename T, std::size_t i>
class nth_iterator<T, i,
                   std::enable_if_t<std::is_same_v<
                       typename std::iterator_traits<T>::iterator_category,
                       std::input_iterator_tag>>> {
 public:
  using iterator_category = std::input_iterator_tag;
  FUZZUF_NTH_ITERATOR_BASIC_OPS
 private:
  T base;
};
template <typename T, std::size_t i>
class nth_iterator<T, i,
                   std::enable_if_t<std::is_same_v<
                       typename std::iterator_traits<T>::iterator_category,
                       std::forward_iterator_tag>>> {
 public:
  using iterator_category = std::forward_iterator_tag;
  FUZZUF_NTH_ITERATOR_BASIC_OPS
  bool operator==(const nth_iterator &r) const { return get() == r.get(); }
  bool operator!=(const nth_iterator &r) const { return get() != r.get(); }

 private:
  T base;
};

template <typename T, std::size_t i>
class nth_iterator<T, i,
                   std::enable_if_t<std::is_same_v<
                       typename std::iterator_traits<T>::iterator_category,
                       std::bidirectional_iterator_tag>>> {
 public:
  using iterator_category = std::bidirectional_iterator_tag;
  FUZZUF_NTH_ITERATOR_BASIC_OPS
  bool operator==(const nth_iterator &r) const { return get() == r.get(); }
  bool operator!=(const nth_iterator &r) const { return get() != r.get(); }
  nth_iterator &operator--() {
    --get();
    return *this;
  }
  nth_iterator operator--(int) {
    auto old = *this;
    get()--;
    return old;
  }

 private:
  T base;
};

template <typename T, std::size_t i>
class nth_iterator<T, i,
                   std::enable_if_t<std::is_same_v<
                       typename std::iterator_traits<T>::iterator_category,
                       std::random_access_iterator_tag>>> {
 public:
  using iterator_category = std::random_access_iterator_tag;
  FUZZUF_NTH_ITERATOR_BASIC_OPS
  bool operator==(const nth_iterator &r) const { return get() == r.get(); }
  bool operator!=(const nth_iterator &r) const { return get() != r.get(); }
  nth_iterator &operator--() {
    --get();
    return *this;
  }
  nth_iterator operator--(int) {
    auto old = *this;
    get()--;
    return old;
  }
  nth_iterator &operator+=(difference_type n) {
    get() += n;
    return *this;
  }
  nth_iterator &operator-=(difference_type n) {
    get() -= n;
    return *this;
  }
  nth_iterator operator+(difference_type n) const {
    return nth_iterator(get() + n);
  }
  nth_iterator operator-(difference_type n) const {
    return nth_iterator(get() - n);
  }
  difference_type operator-(const nth_iterator &r) const {
    return get() - r.get();
  }
  reference operator[](difference_type n) const {
    return std::get<i>(get()[n]);
  }

 private:
  T base;
};

template <typename T, std::size_t i>
auto operator+(typename nth_iterator<T, i>::difference_type l,
               const nth_iterator<T, i> &r)
    -> std::enable_if_t<
        std::is_same_v<typename std::iterator_traits<T>::iterator_category,
                       std::random_access_iterator_tag>,
        nth_iterator<T, i>> {
  return nth_iterator<T, i>(l + r.get());
}

#if __cplusplus >= 202002L
template <typename T, size_t i>
class nth_iterator<T, i,
                   std::enable_if_t<std::is_same_v<
                       typename std::iterator_traits<T>::iterator_category,
                       std::contiguous_iterator_tag>>> {
  using iterator_category = std::random_access_iterator_tag;
  FUZZUF_NTH_ITERATOR_BASIC_OPS
  bool operator==(const nth_iterator &r) const { return get() == r.get(); }
  bool operator!=(const nth_iterator &r) const { return get() != r.get(); }
  nth_iterator &operator--() {
    --get();
    return *this;
  }
  nth_iterator operator--(int) {
    auto old = *this;
    get()--;
    return old;
  }
  nth_iterator &operator+=(difference_type n) {
    get() += n;
    return *this;
  }
  nth_iterator &operator-=(difference_type n) {
    get() -= n;
    return *this;
  }
  nth_iterator operator+(difference_type n) const {
    return nth_iterator(get() + n);
  }
  nth_iterator operator-(difference_type n) const {
    return nth_iterator(get() - n);
  }
  difference_type operator-(const nth_iterator &r) const {
    return get() - r.get();
  }
  reference operator[](difference_type n) const {
    return std::get<i>(get()[n]);
  }

 private:
  T base;
};

template <typename T, std::size_t i>
auto operator+(typename nth_iterator<T, i>::difference_type l,
               const nth_iterator<T, i> &r)
    -> std::enable_if_t<
        std::is_same_v<std::iterator_traits<T>::iterator_category,
                       std::contiguous_iterator_tag>,
        nth_iterator<T, i>> {
  return nth_iterator<T, i>(l + r.get());
}

#endif

template <size_t i, typename R>
using nth_range = boost::iterator_range<nth_iterator<
    utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>, i>>;

template <std::size_t i, typename R>
nth_range<i, R> make_nth_range(R &v) {
  using iterator =
      utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>;
  return nth_range<i, R>(nth_iterator<iterator, i>(v.begin()),
                         nth_iterator<iterator, i>(v.end()));
}

/**
 * @brief Return range adaptor to extract i-th element of std::get-able value
 * @tparam i Return i-th value
 * @tparam R Base range type
 * @param v Base range
 */
template <std::size_t i, typename R>
auto make_nth_range(const R &v) {
  using iterator =
      utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>;
  return boost::make_iterator_range(nth_iterator<iterator, i>(v.begin()),
                                    nth_iterator<iterator, i>(v.end()));
}

namespace adaptor {
template <size_t i>
struct nth_t {};

template <size_t i>
constexpr nth_t<i> nth;

template <size_t i, typename T>
auto operator|(T &p, const nth_t<i> &) {
  return make_nth_range<i, T>(p);
}

template <std::size_t i, typename T>
auto operator|(const T &p, const nth_t<i> &) {
  return make_nth_range<i, T>(p);
}
}  // namespace adaptor

}  // namespace fuzzuf::utils::range
#endif
