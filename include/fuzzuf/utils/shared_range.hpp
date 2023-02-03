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
 * @file shared_range.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_SHARED_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_SHARED_RANGE_HPP
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <type_traits>

#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils::range {
/**
 * @class shared_iterator
 * @brief Iterator adaptor that holds value of U and forward all operations to
 * iterator of type T value of U is copied when this iterator is copied The main
 * purpose of this adaptor is to keep smart pointer to the container during at
 * least one iterator is alive
 *
 * example:
 * std::shared_ptr< std::vector< int > > a{ new std::vector< int >{ ... } };
 * b = a|shared;
 * b behave as same as *a, and keep reference count of a to be incremented until
 * b is destroyed
 */

template <typename T, typename U, typename Enable = void>
class shared_iterator {};
#define FUZZUF_SHARED_ITERATOR_BASIC_OPS                                     \
  using base_iter_t = T;                                                     \
  using difference_type = typename std::iterator_traits<T>::difference_type; \
  using value_type =                                                         \
      std::remove_reference_t<decltype(*std::declval<base_iter_t>())>;       \
  using pointer = void;                                                      \
  using reference = decltype(*std::declval<base_iter_t>());                  \
  shared_iterator() : p(base_iter_t()) {}                                    \
  shared_iterator(const base_iter_t &p_, const std::shared_ptr<U> &sp_)      \
      : p(p_), sp(sp_) {}                                                    \
                                                                             \
  reference operator*() const { return *p; }                                 \
                                                                             \
  base_iter_t &get() { return p; }                                           \
  const base_iter_t &get() const { return p; }                               \
                                                                             \
  shared_iterator &operator++() {                                            \
    ++p;                                                                     \
    return *this;                                                            \
  }                                                                          \
                                                                             \
  shared_iterator operator++(int) {                                          \
    auto old = *this;                                                        \
    p++;                                                                     \
    return old;                                                              \
  }

// requirements: the itartor category of T is input_iterator
template <typename T, typename U>
class shared_iterator<T, std::shared_ptr<U>,
                      std::enable_if_t<std::is_same_v<
                          typename std::iterator_traits<T>::iterator_category,
                          std::input_iterator_tag>>> {
 public:
  using iterator_category = std::input_iterator_tag;
  FUZZUF_SHARED_ITERATOR_BASIC_OPS
 private:
  base_iter_t p;
  std::shared_ptr<U> sp;
};
// requirements: the itartor category of T is forward_iterator
template <typename T, typename U>
class shared_iterator<T, std::shared_ptr<U>,
                      std::enable_if_t<std::is_same_v<
                          typename std::iterator_traits<T>::iterator_category,
                          std::forward_iterator_tag>>> {
 public:
  using iterator_category = std::forward_iterator_tag;
  FUZZUF_SHARED_ITERATOR_BASIC_OPS

  bool operator==(const shared_iterator &r) const { return p == r.p; }

  bool operator!=(const shared_iterator &r) const { return p != r.p; }

 private:
  base_iter_t p;
  std::shared_ptr<U> sp;
};
// requirements: the itartor category of T is bidirectional_iterator
template <typename T, typename U>
class shared_iterator<T, std::shared_ptr<U>,
                      std::enable_if_t<std::is_same_v<
                          typename std::iterator_traits<T>::iterator_category,
                          std::bidirectional_iterator_tag>>> {
 public:
  using iterator_category = std::bidirectional_iterator_tag;
  FUZZUF_SHARED_ITERATOR_BASIC_OPS

  bool operator==(const shared_iterator &r) const { return p == r.p; }

  bool operator!=(const shared_iterator &r) const { return p != r.p; }

  shared_iterator &operator--() {
    --p;
    return *this;
  }

  shared_iterator operator--(int) {
    auto old = *this;
    p--;
    return old;
  }

 private:
  base_iter_t p;
  std::shared_ptr<U> sp;
};
// requirements: the itartor category of T is random_access_iterator
template <typename T, typename U>
class shared_iterator<T, std::shared_ptr<U>,
                      std::enable_if_t<std::is_same_v<
                          typename std::iterator_traits<T>::iterator_category,
                          std::random_access_iterator_tag>>> {
 public:
  using iterator_category = std::random_access_iterator_tag;
  FUZZUF_SHARED_ITERATOR_BASIC_OPS

  bool operator==(const shared_iterator &r) const { return p == r.p; }

  bool operator!=(const shared_iterator &r) const { return p != r.p; }

  shared_iterator &operator--() {
    --p;
    return *this;
  }

  shared_iterator operator--(int) {
    auto old = *this;
    p--;
    return old;
  }

  shared_iterator &operator+=(difference_type n) {
    p += n;
    return *this;
  }

  shared_iterator &operator-=(difference_type n) {
    p -= n;
    return *this;
  }

  shared_iterator operator+(difference_type n) const {
    return shared_iterator(p + n, sp);
  }

  shared_iterator operator-(difference_type n) const {
    return shared_iterator(p - n, sp);
  }

  difference_type operator-(const shared_iterator &r) const { return p - r.p; }

  reference operator[](difference_type n) const { return p[n]; }

 private:
  base_iter_t p;
  std::shared_ptr<U> sp;
};

// requirements: the itartor category of T is random_access_iterator
template <typename T, typename U>
auto operator+(typename shared_iterator<T, U>::difference_type l,
               const shared_iterator<T, U> &r)
    -> std::enable_if_t<
        std::is_same_v<std::iterator_traits<T>::iterator_category,
                       std::random_access_iterator_tag>,
        shared_iterator<T, U>> {
  return r + l;
}

#if __cplusplus >= 202002L
// requirements: the itartor category of T is contiguous_iterator
template <typename T, typename U>
class shared_iterator<T, std::shared_ptr<U>,
                      std::enable_if_t<std::is_same_v<
                          typename std::iterator_traits<T>::iterator_category,
                          std::contiguous_iterator_tag>>> {
  using iterator_category = std::contiguous_iterator_tag;
  FUZZUF_SHARED_ITERATOR_BASIC_OPS

  bool operator==(const shared_iterator &r) const { return p == r.p; }

  bool operator!=(const shared_iterator &r) const { return p != r.p; }

  shared_iterator &operator--() {
    --p;
    return *this;
  }

  shared_iterator operator--(int) {
    auto old = *this;
    p--;
    return old;
  }

  shared_iterator &operator+=(difference_type n) {
    p += n;
    return *this;
  }

  shared_iterator &operator-=(difference_type n) {
    p -= n;
    return *this;
  }

  shared_iterator operator+(difference_type n) const {
    return shared_iterator(p + n, sp);
  }

  shared_iterator operator-(difference_type n) const {
    return shared_iterator(p - n, sp);
  }

  difference_type operator-(const shared_iterator &r) const { return p - r.p; }

  reference operator[](difference_type n) const { return p[n]; }

 private:
  base_iter_t p;
  std::shared_ptr<U> sp;
};

// requirements: the itartor category of T is contiguous_iterator
template <typename T, typename U>
auto operator+(typename shared_iterator<T, U>::difference_type l,
               const shared_iterator<T, U> &r)
    -> std::enable_if_t<
        std::is_same_v<std::iterator_traits<T>::iterator_category,
                       std::contiguous_iterator_tag>,
        shared_iterator<T, U>> {
  return r + l;
}

#endif

template <typename R>
using shared_range = boost::iterator_range<shared_iterator<
    utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>,
    std::shared_ptr<R>>>;

// requirements: R satisfies range concept
template <typename R>
auto make_shared_range(const std::shared_ptr<R> &v) -> std::enable_if_t<
    is_range_v<R>, boost::iterator_range<shared_iterator<RangeIteratorT<R>,
                                                         std::shared_ptr<R>>>> {
  using iterator =
      utils::type_traits::RemoveCvrT<decltype(std::declval<R>().begin())>;
  return boost::make_iterator_range(
      shared_iterator<iterator, std::shared_ptr<R>>(v->begin(), v),
      shared_iterator<iterator, std::shared_ptr<R>>(v->end(), v));
}

namespace adaptor {
struct shared_t {};
constexpr shared_t shared;

template <typename T>
auto operator|(const std::shared_ptr<T> &p, const shared_t &)
    -> decltype(make_shared_range(std::declval<const std::shared_ptr<T> &>())) {
  return make_shared_range(p);
}

}  // namespace adaptor

}  // namespace fuzzuf::utils::range
#endif
