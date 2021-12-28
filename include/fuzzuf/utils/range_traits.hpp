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
#ifndef FUZZUF_INCLUDE_UTILS_RANGE_TRAITS_HPP
#define FUZZUF_INCLUDE_UTILS_RANGE_TRAITS_HPP
#include "fuzzuf/utils/check_capability.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include "fuzzuf/utils/void_t.hpp"
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>
namespace fuzzuf::utils::range {

/**
 * @class IsIterator
 * @brief TがC++17 §24.2.1-1の要件を満たす場合trueを返す
 * @tparm T 任意の型
 */
template <typename T, typename Enable = void>
struct IsIterator : public std::false_type {};
template <typename T>
struct IsIterator<
    T, utils::void_t<decltype(*std::declval<T>()),
                     decltype(++std::declval<utils::type_traits::RemoveCvrT<
                                  unsigned char *> &>()),
                     decltype(std::declval<utils::type_traits::RemoveCvrT<
                                  unsigned char *> &>()++)>>
    : public std::true_type {};
template <typename T> constexpr bool is_iterator_v = IsIterator<T>::value;

/**
 * @class IsRange
 * @brief
 * Tがメンバ関数begin()とend()を持ち、その返り値の型のis_iteratorがtrueである場合trueを返す
 * @tparm T 任意の型
 */
template <typename T, typename Enable = void>
struct IsRange : public std::false_type {};
template <typename T>
struct IsRange<
    T,
    std::enable_if_t<
        is_iterator_v<decltype(
            std::declval<T>().begin())> && // Tにはbegin()がある
        is_iterator_v<decltype(std::declval<T>().end())> // Tにはend()がある
        >> : public std::true_type {};
template <typename T> constexpr bool is_range_v = IsRange<T>::value;

/**
 * @class RangeValue
 * @brief Rangeのis_rangeがtrueの場合にrangeのvalue_typeを取得する
 * @tparm Range 任意の型
 */
template <typename Range, typename Enable = void> struct RangeValue {};
template <typename Range>
struct RangeValue<Range,
                  std::enable_if_t<is_range_v<Range> // Rangeはrangeである
                                   >> {
  using type =
      type_traits::RemoveCvrT<decltype(*std::declval<Range>().begin())>;
};

template <typename Range> using RangeValueT = typename RangeValue<Range>::type;

/**
 * @class RangeIterator
 * @brief Rangeのis_rangeがtrueの場合にrangeのiteratorを取得する
 * @tparm Range 任意の型
 */
template <typename Range, typename Enable = void> struct RangeIterator {};
template <typename Range>
struct RangeIterator<Range,
                     std::enable_if_t<is_range_v<Range> // Rangeはrangeである
                                      >> {
  using type = type_traits::RemoveCvrT<decltype(std::declval<Range>().begin())>;
};
template <typename Range>
using RangeIteratorT = typename RangeIterator<Range>::type;

/**
 * @class is_range_of
 * @brief Rangeのis_rangeがtrueかつRangeのRangeValueがTの場合にtrueを返す
 * @tparm Range 任意の型
 * @tparm T 要素の型
 */
template <typename Range, typename T, typename Enable = void>
struct IsRangeOf : public std::false_type {};
template <typename Range, typename T>
struct IsRangeOf<Range, T, std::enable_if_t<is_range_v<Range>>>
    : public std::is_same<utils::range::RangeValueT<Range>, T> {};
template <typename Range, typename T>
constexpr bool is_range_of_v = IsRangeOf<Range, T>::value;

/**
 * @class is_integral_range
 * @brief Rangeのis_rangeがtrueかつRangeのRangeValueが整数の場合にtrueを返す
 * @tparm Range 任意の型
 */
template <typename Range, typename Enable = void>
struct IsIntegralRange : public std::false_type {};
template <typename Range>
struct IsIntegralRange<Range, std::enable_if_t<is_range_v<Range>>>
    : public std::is_integral<utils::range::RangeValueT<Range>> {};
template <typename Range>
constexpr bool is_integral_range_v = IsIntegralRange<Range>::value;

// メンバ関数erase( iter, iter )がある
FUZZUF_CHECK_CAPABILITY(HasErase, has_erase,
                        std::declval<T &>().erase(std::declval<T &>().begin(),
                                                  std::declval<T &>().end()))
// メンバ関数insert( iter, value )がある
FUZZUF_CHECK_CAPABILITY(
    HasInsertValue, has_insert_value,
    std::declval<T &>().insert(std::declval<T &>().begin(),
                               std::declval<RangeValueT<T>>()))
// メンバ関数insert( iter, n, value )がある
FUZZUF_CHECK_CAPABILITY(
    HasInsertValueN, has_insert_value_n,
    std::declval<T &>().insert(std::declval<T &>().begin(), 3u,
                               std::declval<RangeValueT<T>>()))
// メンバ関数insert( iter, iter, iter )がある
FUZZUF_CHECK_CAPABILITY(HasInsertRange, has_insert_range,
                        std::declval<T &>().insert(std::declval<T &>().begin(),
                                                   std::declval<T &>().begin(),
                                                   std::declval<T &>().begin()))
// メンバ関数push_back( value )がある
FUZZUF_CHECK_CAPABILITY(
    HasPushBack, has_push_back,
    std::declval<T &>().push_back(std::declval<RangeValueT<T>>()))
// メンバ関数assign( iter, iter )がある
FUZZUF_CHECK_CAPABILITY(HasAssign, has_assign,
                        std::declval<T &>().assign(std::declval<T &>().begin(),
                                                   std::declval<T &>().begin()))
// メンバ関数clear()がある
FUZZUF_CHECK_CAPABILITY(HasClear, has_clear, std::declval<T &>().clear())
// メンバ関数empty()がある
FUZZUF_CHECK_CAPABILITY(HasEmpty, has_empty, std::declval<T &>().empty())
// メンバ関数size()がある
FUZZUF_CHECK_CAPABILITY(HasSize, has_size, std::declval<T &>().size())
// メンバ関数data()がある
FUZZUF_CHECK_CAPABILITY(HasData, has_data, std::declval<T &>().data())
// メンバ関数resize( size )がある
FUZZUF_CHECK_CAPABILITY(HasResize, has_resize, std::declval<T &>().resize(1u))

/**
 * @fn
 * rangeの長さを返す
 * @tparm R メンバ関数size()を持つ任意の型
 * @param r メンバ関数size()を持つ任意の型の値
 */
template <typename R>
auto rangeSize(const R &r)
    -> std::enable_if_t<has_size_v<R>, // Rにはメンバ関数size()がある
                        std::size_t> {
  return r.size();
}

/**
 * @fn
 * rangeの長さを返す
 * @tparm R メンバ関数begin()とend()を持つ任意の型
 * @param r メンバ関数begin()とend()を持つ任意の型の値
 */
template <typename R>
auto rangeSize(const R &r)
    -> std::enable_if_t<!has_size_v<R>, // Rにはメンバ関数size()がない
                        std::size_t> {
  return std::distance(r.begin(), r.end());
}

/**
 * @fn
 * rangeが空の場合にtrueを返す
 * @tparm R メンバ関数empty()を持つ任意の型
 * @param r メンバ関数empty()を持つ任意の型の値
 */
template <typename R>
auto rangeEmpty(const R &r)
    -> std::enable_if_t<has_empty_v<R>, // Rにはメンバ関数empty()がある
                        std::size_t> {
  return r.empty();
}

/**
 * @fn
 * rangeが空の場合にtrueを返す
 * @tparm R メンバ関数begin()とend()を持つ任意の型
 * @param r メンバ関数begin()とend()を持つ任意の型の値
 */
template <typename R>
auto rangeEmpty(const R &r)
    -> std::enable_if_t<!has_empty_v<R>, // Rにはメンバ関数empty()がない
                        std::size_t> {
  return r.begin() == r.end();
}

/**
 * @fn
 * r2にr1を代入する
 * @tparm R1 R2に代入可能な任意の型
 * @tparm R2 R1を代入可能な任意の型
 * @param r1 この値を代入する
 * @param r2 この参照先に代入される
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<std::is_assignable_v<R2 &, const R1 &>> {
  r2 = r1;
}

/**
 * @fn
 * r2にr1を代入する
 * @tparm R1 メンバ関数begin()とend()を持つ任意の型
 * @tparm R2 メンバ関数assign()を持つ任意の型
 * @param r1 この値を代入する
 * @param r2 この参照先に代入される
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!std::is_assignable_v<R2 &, const R1 &> &&
                        has_assign_v<R2>> {
  r2.assign(r1.begin(), r1.end());
}

/**
 * @fn
 * r2にr1を代入する
 * @tparm R1 メンバ関数begin()とend()を持つ任意の型
 * @tparm R2 メンバ関数clear()とinsert()を持つ任意の型
 * @param r1 この値を代入する
 * @param r2 この参照先に代入される
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!std::is_assignable_v<R2, const R1> &&
                        !has_assign_v<R2> && has_clear_v<R2> &&
                        has_insert_range_v<R2>> {
  r2.clear();
  r2.insert(r2.begin(), r1.begin(), r1.end());
}

/**
 * @fn
 * r2にr1を代入する
 * @tparm R1 メンバ関数begin()とend()を持つ任意の型
 * @tparm R2 メンバ関数clear()とpush_back()を持つ任意の型
 * @param r1 この値を代入する
 * @param r2 この参照先に代入される
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!std::is_assignable_v<R2, const R1> &&
                        !has_assign_v<R2> && has_clear_v<R2> &&
                        !has_insert_range_v<R2> && has_push_back_v<R2>> {
  r2.clear();
  std::copy(r1.begin(), r1.end(), std::back_inserter(r2));
}

/**
 * @fn
 * r2にr1を代入する
 * @tparm R1 メンバ関数begin()とend()を持つ任意の型
 * @tparm R2 メンバ関数begin()とresize()を持つ任意の型
 * @param r1 この値を代入する
 * @param r2 この参照先に代入される
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!std::is_assignable_v<R2, const R1> &&
                        !has_assign_v<R2> && !has_insert_range_v<R2> &&
                        !has_push_back_v<R2> && has_resize_v<R2>> {
  r2.resize(rangeSize(r1));
  std::copy(r1.begin(), r1.end(), r2.begin());
}

/**
 * @class directly_appendable
 * @brief R1とR2で+=による加算が可能な場合trueを返す
 * @tparm R1 任意の型
 * @tparm R2 任意の型
 */
template <typename R1, typename R2, typename Enable = void>
struct DirectlyAppendable : public std::false_type {};
template <typename R1, typename R2>
struct DirectlyAppendable<
    R1, R2, utils::void_t<decltype(std::declval<R1>() += std::declval<R2>())>>
    : public std::true_type {};
template <typename R1, typename R2>
constexpr bool directly_appendable_v = DirectlyAppendable<R1, R2>::value;

/**
 * @class is_convertible_range
 * @brief R1のRangeValueをR2のRangeValueに暗黙に変換可能な場合trueが返る
 * @tparm R1 任意の型
 * @tparm R2 任意の型
 */
template <typename R1, typename R2, typename Enable = void>
struct IsConvertibleRange : public std::false_type {};
template <typename R1, typename R2>
struct IsConvertibleRange<
    R1, R2,
    std::enable_if_t<std::is_convertible_v<RangeValueT<R1>, RangeValueT<R2>>>>
    : public std::true_type {};
template <typename R1, typename R2>
constexpr bool is_convertible_range_v = IsConvertibleRange<R1, R2>::value;

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1 R2に+=できる任意の型
 * @tparm R2 R1を+=できる任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<directly_appendable_v<R2 &, const R1 &>> {
  r2 += r1;
}

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1
 * メンバ関数begin()とend()を持ちR2とconvertible_rangeであるような任意の型
 * @tparm R2
 * メンバ関数end()とinsert()を持ちR1とconvertible_rangeであるような任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        is_convertible_range_v<R1, R2> &&
                        has_insert_range_v<R2>> {
  r2.insert(r2.end(), r1.begin(), r1.end());
}

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1 R2のvalue_typeに暗黙に変換可能な任意の型
 * @tparm R2 メンバ関数end()とinsert()を持つ任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        !is_convertible_range_v<R1, R2> &&
                        has_insert_value_v<R2>> {
  r2.insert(r2.end(), r1);
}

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1
 * メンバ関数begin()とend()を持ちR2とconvertible_rangeであるような任意の型
 * @tparm R2
 * メンバ関数end()とpush_back()を持ちR1とconvertible_rangeであるような任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        is_convertible_range_v<R1, R2> &&
                        !has_insert_range_v<R2> && has_push_back_v<R2>> {
  std::copy(r1.begin(), r1.end(), std::back_inserter(r2));
}

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1 R2のvalue_typeに暗黙に変換可能な任意の型
 * @tparm R2 メンバ関数end()とpush_back()を持つ任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        !is_convertible_range_v<R1, R2> &&
                        !has_insert_value_v<R2> && has_push_back_v<R2>> {
  r2.push_back(r1);
}

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1
 * メンバ関数begin()とend()を持ちR2とconvertible_rangeであるような任意の型
 * @tparm R2
 * メンバ関数resize()とbegin()を持ちR1とconvertible_rangeであるような任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        is_convertible_range_v<R1, R2> &&
                        !has_insert_range_v<R2> && !has_push_back_v<R2> &&
                        has_resize_v<R2>> {
  auto old_size = rangeSize(r2);
  r2.resize(rangeSize(r1) + old_size);
  std::copy(r1.begin(), r1.end(), std::next(r2.begin(), old_size));
}

/**
 * @fn
 * r2にr1を追加する
 * @tparm R1 R2のvalue_typeに暗黙に変換可能な任意の型
 * @tparm R2 メンバ関数resize()とbegin()を持つ任意の型
 * @param r1 この値を追加する
 * @param r2 この参照先に追加する
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        !is_convertible_range_v<R1, R2> &&
                        !has_insert_value_v<R2> && !has_push_back_v<R2> &&
                        has_resize_v<R2>> {
  auto old_size = rangeSize(r2);
  r2.resize(old_size + 1u);
  *std::next(r2.begin(), old_size) = r1;
}

/**
 * @fn
 * remove all elements in the range
 * ( for the case R has clear() )
 * @tparm R A type that meets the standard range concept and has clear()
 * @param r range to remove elements
 */
template <typename R> auto clear(R &r) -> std::enable_if_t<has_clear_v<R>> {
  r.clear();
}

/**
 * @fn
 * remove all elements in the range
 * ( for the case R doesn't have clear() )
 * @tparm R A type that meets the standard range concept but clear() is not
 * available
 * @param r range to remove elements
 */
template <typename R> auto clear(R &r) -> std::enable_if_t<!has_clear_v<R>> {
  r = R();
}

/**
 * @class
 * @brief Tがassignで代入できるrangeの場合にtrueを返す
 * @tparm T 任意の型
 */
template <typename T, typename Enable = void>
struct IsAssignableRange : public std::false_type {};
template <typename T>
struct IsAssignableRange<T, std::enable_if_t<has_assign_v<T>>>
    : public std::true_type {};
template <typename T>
struct IsAssignableRange<T,
                         std::enable_if_t<!has_assign_v<T> && has_clear_v<T> &&
                                          has_insert_range_v<T>>>
    : public std::true_type {};
template <typename T>
struct IsAssignableRange<
    T, std::enable_if_t<!has_assign_v<T> && has_clear_v<T> &&
                        !has_insert_range_v<T> && has_push_back_v<T>>>
    : public std::true_type {};
template <typename T>
struct IsAssignableRange<
    T, std::enable_if_t<!has_assign_v<T> && !has_insert_range_v<T> &&
                        !has_push_back_v<T> && has_resize_v<T>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_assignable_range_v = IsAssignableRange<T>::value;

/**
 * @fn
 * rangeからrangeへ値を代入する
 * @tparm R1 rangeの要件を満たす任意の型
 * @tparm R2 rangeの要件を満たす任意の型
 * @param r1 この値を代入する
 * @param r2 この参照先に代入される
 */
template <typename R1, typename R2>
auto copy(const R1 &r1, R2 &r2)
    -> std::enable_if_t<is_range_v<R1> && is_range_v<R2> &&
                        (std::is_assignable_v<R2 &, const R1 &> ||
                         is_assignable_range_v<R2>)> {
  assign(r1, r2);
}

/**
 * @fn
 * rangeからoutput iteratorへ値を代入する
 * @tparm R1 rangeの要件を満たす任意の型
 * @tparm R2 output iteratorの要件を満たす任意の型
 * @param r1 この値を代入する
 * @param r2 このイテレータに代入される
 */
template <typename R, typename I>
auto copy(const R &r, I dest)
    -> std::enable_if_t<is_range_v<R> && !is_range_v<I> && is_iterator_v<I>> {
  std::copy(r.begin(), r.end(), dest);
}

} // namespace fuzzuf::utils::range
#endif
