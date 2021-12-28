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
#ifndef FUZZUF_INCLUDE_UTILS_FILTERED_RANGE_HPP
#define FUZZUF_INCLUDE_UTILS_FILTERED_RANGE_HPP
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include <boost/range/iterator_range.hpp>
#include <memory>
#include <stdexcept>
#include <type_traits>
namespace fuzzuf::utils::range {
// U型の値を持ちT型のイテレータに対する操作を全てforwardingする
// U型の値はイテレータをコピーすると一緒にコピーされる
// UにT型のイテレータの持ち主のコンテナへのスマートポインタを渡す事で、イテレータが1つでも残っている限りコンテナが消えないように出来る
/*
 * 例:
 * std::vector< int > a{ ... };
 * b = a|filtered[ []( int v ) { return v < 10; } ];
 * bはaの要素のうち10未満の値だけを含むrangeになる
 * std::filterしてstd::transformみたいな状況でfilterした結果を一時領域に書く必要がなくなる
 *
 * Boost.Rangeのfilteredとほぼ同じ振る舞いをするが、bidirectional_iteratorを渡された場合にrangeのイテレータががbidirectional_iteratorになる点が異なる
 * https://www.boost.org/doc/libs/1_52_0/libs/range/doc/html/range/reference/adaptors/reference/filtered.html
 */
template <typename T, typename U, typename Enable = void>
class filtered_iterator {};
#define FUZZUF_FILTERED_ITERATOR_BASIC_OPS                                     \
  using base_iter_t = T;                                                       \
  using difference_type = typename std::iterator_traits<T>::difference_type;   \
  using value_type =                                                           \
      std::remove_reference_t<decltype(*std::declval<base_iter_t>())>;         \
  using pointer = void;                                                        \
  using reference = decltype(*std::declval<base_iter_t>());                    \
  filtered_iterator(const base_iter_t &p_, const base_iter_t &end_, U cond_)   \
      : p(p_), end(end_), cond(cond_) {                                        \
    if (p != end) {                                                            \
      p = std::find_if(p, end, cond);                                          \
    }                                                                          \
  }                                                                            \
                                                                               \
  reference operator*() const {                                                \
    if (p == end)                                                              \
      throw std::out_of_range("filtered_iterator::operator*()");               \
    return *p;                                                                 \
  }                                                                            \
                                                                               \
  base_iter_t &get() { return p; }                                             \
  const base_iter_t &get() const { return p; }                                 \
                                                                               \
  filtered_iterator &operator++() {                                            \
    if (p != end) {                                                            \
      ++p;                                                                     \
      p = std::find_if(p, end, cond);                                          \
    }                                                                          \
    return *this;                                                              \
  }                                                                            \
                                                                               \
  filtered_iterator operator++(int) {                                          \
    auto old = *this;                                                          \
    if (p != end) {                                                            \
      ++p;                                                                     \
      p = std::find_if(p, end, cond);                                          \
    }                                                                          \
    return old;                                                                \
  }

// 条件: Tのイテレータカテゴリはinput_iteratorである
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
// 条件: Tのイテレータカテゴリはforward_iteratorである
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

// 条件: Rはrangeである
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
template <typename U> struct filtered_t { U cond; };
template <typename U> filtered_t<U> filtered(U cond) {
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

} // namespace adaptor

} // namespace fuzzuf::utils::range
#endif
