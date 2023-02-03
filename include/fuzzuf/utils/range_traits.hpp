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
 * @file range_traits.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_RANGE_TRAITS_HPP
#define FUZZUF_INCLUDE_UTILS_RANGE_TRAITS_HPP
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>

#include "fuzzuf/utils/check_capability.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include "fuzzuf/utils/void_t.hpp"
namespace fuzzuf::utils::range {

/**
 * @class IsIterator
 * @brief Meta function that returns true if T satisfies C++17 §24.2.1-1
 * requirements
 * @tparam T Type to check
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
template <typename T>
constexpr bool is_iterator_v = IsIterator<T>::value;

/**
 * @class IsRange
 * @brief Meta function that returns true if T has member function begin() and
 * end() and the return type of those functions satisfies is_iterator
 * @tparam T Type to check
 */
template <typename T, typename Enable = void>
struct IsRange : public std::false_type {};
template <typename T>
struct IsRange<
    T,
    std::enable_if_t<
        is_iterator_v<
            decltype(std::declval<T>().begin())> &&  // Tにはbegin()がある
        is_iterator_v<decltype(std::declval<T>().end())>  // Tにはend()がある
        >> : public std::true_type {};
template <typename T>
constexpr bool is_range_v = IsRange<T>::value;

/**
 * @class RangeValue
 * @brief Meta function that returns value_type of Range if Range satisfies
 * is_range Otherwise, type is not defined
 * @tparam Range Range type
 */
template <typename Range, typename Enable = void>
struct RangeValue {};
template <typename Range>
struct RangeValue<Range,
                  std::enable_if_t<is_range_v<Range>  // Range is range
                                   >> {
  using type =
      type_traits::RemoveCvrT<decltype(*std::declval<Range>().begin())>;
};

template <typename Range>
using RangeValueT = typename RangeValue<Range>::type;

/**
 * @class RangeIterator
 * @brief Meta function that returns iterator of Range if Range satisfies
 * is_range Otherwise, type is not defined
 * @tparam Range Range type
 */
template <typename Range, typename Enable = void>
struct RangeIterator {};
template <typename Range>
struct RangeIterator<Range,
                     std::enable_if_t<is_range_v<Range>  // Range is range
                                      >> {
  using type = type_traits::RemoveCvrT<decltype(std::declval<Range>().begin())>;
};
template <typename Range>
using RangeIteratorT = typename RangeIterator<Range>::type;

/**
 * @class is_range_of
 * @brief Meta function that returns true if Range satisfies is_range and the
 * value_type is same as T If Range doesn't satisfy is_range, value is not
 * defined
 * @tparam Range Range type
 * @tparam T Expected value type
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
 * @brief Meta function that returns true if Range satisfies is_range and the
 * value_type is integral If Range doesn't satisfy is_range, value is not
 * defined
 * @tparam Range Range type
 */
template <typename Range, typename Enable = void>
struct IsIntegralRange : public std::false_type {};
template <typename Range>
struct IsIntegralRange<Range, std::enable_if_t<is_range_v<Range>>>
    : public std::is_integral<utils::range::RangeValueT<Range>> {};
template <typename Range>
constexpr bool is_integral_range_v = IsIntegralRange<Range>::value;

// Check if the type has member function erase( iter, iter )
FUZZUF_CHECK_CAPABILITY(HasErase, has_erase,
                        std::declval<T &>().erase(std::declval<T &>().begin(),
                                                  std::declval<T &>().end()))
// Check if the type has member function insert( iter, value )
FUZZUF_CHECK_CAPABILITY(
    HasInsertValue, has_insert_value,
    std::declval<T &>().insert(std::declval<T &>().begin(),
                               std::declval<RangeValueT<T>>()))
// Check if the type has member function insert( iter, n, value )
FUZZUF_CHECK_CAPABILITY(
    HasInsertValueN, has_insert_value_n,
    std::declval<T &>().insert(std::declval<T &>().begin(), 3u,
                               std::declval<RangeValueT<T>>()))
// Check if the type has member function insert( iter, iter, iter )
FUZZUF_CHECK_CAPABILITY(HasInsertRange, has_insert_range,
                        std::declval<T &>().insert(std::declval<T &>().begin(),
                                                   std::declval<T &>().begin(),
                                                   std::declval<T &>().begin()))
// Check if the type has member function push_back( value )
FUZZUF_CHECK_CAPABILITY(
    HasPushBack, has_push_back,
    std::declval<T &>().push_back(std::declval<RangeValueT<T>>()))
// Check if the type has member function assign( iter, iter )
FUZZUF_CHECK_CAPABILITY(HasAssign, has_assign,
                        std::declval<T &>().assign(std::declval<T &>().begin(),
                                                   std::declval<T &>().begin()))
// Check if the type has member function clear()
FUZZUF_CHECK_CAPABILITY(HasClear, has_clear, std::declval<T &>().clear())
// Check if the type has member function empty()
FUZZUF_CHECK_CAPABILITY(HasEmpty, has_empty, std::declval<T &>().empty())
// Check if the type has member function size()
FUZZUF_CHECK_CAPABILITY(HasSize, has_size, std::declval<T &>().size())
// Check if the type has member function data()
FUZZUF_CHECK_CAPABILITY(HasData, has_data, std::declval<T &>().data())
// Check if the type has member function resize( size )
FUZZUF_CHECK_CAPABILITY(HasResize, has_resize, std::declval<T &>().resize(1u))

/**
 * Return the size of range
 * Roughly compatible to C++20 std::ranges::size
 * @tparam R Type with member function size()
 * @param r Value of R
 */
template <typename R>
auto rangeSize(const R &r) -> std::enable_if_t<has_size_v<R>,  // R has size()
                                               std::size_t> {
  return r.size();
}

/**
 * Return the size of range
 * Roughly compatible to C++20 std::ranges::size
 * @tparam R Type with member function begin() and end()
 * @param r Value of R
 */
template <typename R>
auto rangeSize(const R &r)
    -> std::enable_if_t<!has_size_v<R>,  // R doesn't have size()
                        std::size_t> {
  return std::distance(r.begin(), r.end());
}

/**
 * Return true if the range is empty
 * Roughly compatible to C++20 std::ranges::empty
 * @tparam R Type with member function empty()
 * @param r Value of R
 */
template <typename R>
auto rangeEmpty(const R &r)
    -> std::enable_if_t<has_empty_v<R>,  // R has empty()
                        std::size_t> {
  return r.empty();
}

/**
 * Return true if the range is empty
 * Roughly compatible to C++20 std::ranges::empty
 * @tparam R Type with member function begin() and end()
 * @param r Value of R
 */
template <typename R>
auto rangeEmpty(const R &r)
    -> std::enable_if_t<!has_empty_v<R>,  // Rにはメンバ関数empty()がない
                        std::size_t> {
  return r.begin() == r.end();
}

/**
 * Assign r1 to r2
 * @tparam R1 Type that can be assigned to R2
 * @tparam R2 Type that can assign R1
 * @param r1 This value is assigned
 * @param r2 Assign to this value
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<std::is_assignable_v<R2 &, const R1 &>> {
  r2 = r1;
}

/**
 * Assign r1 to r2
 * @tparam R1 Type with member function begin() and end()
 * @tparam R2 Type with member function assign
 * @param r1 This value is assigned
 * @param r2 Assign to this value
 */
template <typename R1, typename R2>
auto assign(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!std::is_assignable_v<R2 &, const R1 &> &&
                        has_assign_v<R2>> {
  r2.assign(r1.begin(), r1.end());
}

/**
 * Assign r1 to r2
 * @tparam R1 Type with member function begin() and end()
 * @tparam R2 Type with member function clear() and insert()
 * @param r1 This value is assigned
 * @param r2 Assign to this value
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
 * Assign r1 to r2
 * @tparam R1 Type with member function begin() and end()
 * @tparam R2 Type with member function clear() and push_back()
 * @param r1 This value is assigned
 * @param r2 Assign to this value
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
 * Assign r1 to r2
 * @tparam R1 Type with member function begin() and end()
 * @tparam R2 Type with member function begin() and resize()
 * @param r1 This value is assigned
 * @param r2 Assign to this value
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
 * @brief Meta function that returns true if operator+= is defined for R1 and R2
 * @tparam R1 Any type
 * @tparam R2 Any type
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
 * @brief Meta function that returns true if RangeValue of R1 can cast to
 * RangeValue of R2 implicitly
 * @tparam R1 Any type
 * @tparam R2 Any type
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
 * Append r1 to r2
 * @tparam R1 Type that can be appended to R2 by +=
 * @tparam R2 Type that can append R1 by +=
 * @param r1 This value is appended
 * @param r2 Append to this value
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<directly_appendable_v<R2 &, const R1 &>> {
  r2 += r1;
}

/**
 * Append r1 to r2
 * @tparam R1 Type with member function begin() and end() that satisfies
 * convertible_range with R2
 * @tparam R2 Type with member function end() and insert() that satisfies
 * convertible_range with R1
 * @param r1 This value is appended
 * @param r2 Append to this value
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        is_convertible_range_v<R1, R2> &&
                        has_insert_range_v<R2>> {
  r2.insert(r2.end(), r1.begin(), r1.end());
}

/**
 * Append r1 to r2
 * @tparam R1 Type that can cast to value_type of R2 implicitly
 * @tparam R2 Type with member function end() and insert()
 * @param r1 This value is appended
 * @param r2 Append to this value
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        !is_convertible_range_v<R1, R2> &&
                        has_insert_value_v<R2>> {
  r2.insert(r2.end(), r1);
}

/**
 * Append r1 to r2
 * @tparam R1 Type that can cast to value_type of R2 implicitly
 * @tparam R1 Type with member function begin() and end() that satisfies
 * convertible_range with R2
 * @tparam R2 Type with member function end() and push_back() that satisfies
 * convertible_range with R1
 * @param r1 This value is appended
 * @param r2 Append to this value
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        is_convertible_range_v<R1, R2> &&
                        !has_insert_range_v<R2> && has_push_back_v<R2>> {
  std::copy(r1.begin(), r1.end(), std::back_inserter(r2));
}

/**
 * Append r1 to r2
 * @tparam R1 Type that can cast to value_type of R2 implicitly
 * @tparam R2 Type with member function end() and push_back()
 * @param r1 This value is appended
 * @param r2 Append to this value
 */
template <typename R1, typename R2>
auto append(const R1 &r1, R2 &r2)
    -> std::enable_if_t<!directly_appendable_v<R2 &, const R1 &> &&
                        !is_convertible_range_v<R1, R2> &&
                        !has_insert_value_v<R2> && has_push_back_v<R2>> {
  r2.push_back(r1);
}

/**
 * Append r1 to r2
 * @tparam R1 Type that can cast to value_type of R2 implicitly
 * @tparam R1 Type with member function begin() and end() that satisfies
 * convertible_range with R2
 * @tparam R2 Type with member function resize) and begin() that satisfies
 * convertible_range with R1
 * @param r1 This value is appended
 * @param r2 Append to this value
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
 * Append r1 to r2
 * @tparam R1 Type that can cast to value_type of R2 implicitly
 * @tparam R2 Type with member function resize() and begin()
 * @param r1 This value is appended
 * @param r2 Append to this value
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
 * remove all elements in the range
 * ( for the case R has clear() )
 * @tparam R A type that meets the standard range concept and has clear()
 * @param r Range to remove elements
 */
template <typename R>
auto clear(R &r) -> std::enable_if_t<has_clear_v<R>> {
  r.clear();
}

/**
 * remove all elements in the range
 * ( for the case R doesn't have clear() )
 * @tparam R A type that meets the standard range concept but clear() is not
 * available
 * @param r Range to remove elements
 */
template <typename R>
auto clear(R &r) -> std::enable_if_t<!has_clear_v<R>> {
  r = R();
}

/**
 * @class
 * @brief Meta function that returns true if T is range that can be left hand
 * side value of assign()
 * @tparam T Type to check
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
 * assign range values to other range
 * @tparam R1 Type that satisfies range concept
 * @tparam R2 Type that satisfies range concept
 * @param r1 This value is assigned
 * @param r2 Assign to this value
 */
template <typename R1, typename R2>
auto copy(const R1 &r1, R2 &r2)
    -> std::enable_if_t<is_range_v<R1> && is_range_v<R2> &&
                        (std::is_assignable_v<R2 &, const R1 &> ||
                         is_assignable_range_v<R2>)> {
  assign(r1, r2);
}

/**
 * assign range values to output iterator
 * @tparam R1 Type that satisfies range concept
 * @tparam R2 Type that satisfies output iterator concept
 * @param r1 This value is assigned
 * @param r2 Assign to this value
 */
template <typename R, typename I>
auto copy(const R &r, I dest)
    -> std::enable_if_t<is_range_v<R> && !is_range_v<I> && is_iterator_v<I>> {
  std::copy(r.begin(), r.end(), dest);
}

}  // namespace fuzzuf::utils::range
#endif
