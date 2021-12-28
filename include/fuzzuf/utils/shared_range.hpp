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
#ifndef FUZZUF_INCLUDE_UTILS_SHARED_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_SHARED_RANGE_HPP
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <type_traits>
namespace fuzzuf::utils::range {
// U型の値を持ちT型のイテレータに対する操作を全てforwardingする
// U型の値はイテレータをコピーすると一緒にコピーされる
// UにT型のイテレータの持ち主のコンテナへのスマートポインタを渡す事で、イテレータが1つでも残っている限りコンテナが消えないように出来る
/*
 * 例:
 * std::shared_ptr< std::vector< int > > a{ new std::vector< int >{ ... } };
 * b = a|shared;
 * bは*aと同じ振る舞いをし、bが破棄されるまでaの参照カウントを上げたままにするrangeになる
 * rangeを要求している関数に「使い終わったら破棄しておいて」まで任せるのに便利
 */

template <typename T, typename U, typename Enable = void>
class shared_iterator {};
#define FUZZUF_SHARED_ITERATOR_BASIC_OPS                                       \
  using base_iter_t = T;                                                       \
  using difference_type = typename std::iterator_traits<T>::difference_type;   \
  using value_type =                                                           \
      std::remove_reference_t<decltype(*std::declval<base_iter_t>())>;         \
  using pointer = void;                                                        \
  using reference = decltype(*std::declval<base_iter_t>());                    \
  shared_iterator(const base_iter_t &p_, const std::shared_ptr<U> &sp_)        \
      : p(p_), sp(sp_) {}                                                      \
                                                                               \
  reference operator*() const { return *p; }                                   \
                                                                               \
  base_iter_t &get() { return p; }                                             \
  const base_iter_t &get() const { return p; }                                 \
                                                                               \
  shared_iterator &operator++() {                                              \
    ++p;                                                                       \
    return *this;                                                              \
  }                                                                            \
                                                                               \
  shared_iterator operator++(int) {                                            \
    auto old = *this;                                                          \
    p++;                                                                       \
    return old;                                                                \
  }

// 条件: Tのイテレータカテゴリはinput_iteratorである
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
// 条件: Tのイテレータカテゴリはforward_iteratorである
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
// 条件: Tのイテレータカテゴリはbidirectional_iteratorである
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
// 条件: Tのイテレータカテゴリはrandom_access_iteratorである
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

// 条件: Tのイテレータカテゴリはrandom_access_iteratorである
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
// 条件: Tのイテレータカテゴリはcontiguous_iteratorである
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

// 条件: Tのイテレータカテゴリはcontiguous_iteratorである
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
// 条件: Rはrangeである
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

} // namespace adaptor

} // namespace fuzzuf::utils::range
#endif
