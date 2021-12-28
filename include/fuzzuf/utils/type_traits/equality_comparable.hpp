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
#ifndef FUZZUF_INCLUDE_UTILS_EQUALITY_COMPARABLE_HPP
#define FUZZUF_INCLUDE_UTILS_EQUALITY_COMPARABLE_HPP

#include "fuzzuf/utils/void_t.hpp"
#include <type_traits>

namespace fuzzuf::utils::type_traits {
namespace detail {
template <typename T, typename U, typename Enable = void>
struct is_weakly_equality_comparable_with : public std::false_type {};
template <typename T, typename U>
struct is_weakly_equality_comparable_with<
    T, U,
    utils::void_t<
        decltype(
            std::declval<const typename std::remove_reference<T>::type &>() ==
            std::declval<const typename std::remove_reference<U>::type &>()),
        decltype(
            std::declval<const typename std::remove_reference<T>::type &>() !=
            std::declval<const typename std::remove_reference<U>::type &>()),
        decltype(
            std::declval<const typename std::remove_reference<U>::type &>() ==
            std::declval<const typename std::remove_reference<T>::type &>()),
        decltype(
            std::declval<const typename std::remove_reference<U>::type &>() !=
            std::declval<const typename std::remove_reference<T>::type &>())>>
    : public std::integral_constant<
          bool,
          std::is_same<
              bool, decltype(std::declval<const typename std::remove_reference<
                                 T>::type &>() ==
                             std::declval<const typename std::remove_reference<
                                 U>::type &>())>::value &&
              std::is_same<
                  bool,
                  decltype(std::declval<const typename std::remove_reference<
                               T>::type &>() !=
                           std::declval<const typename std::remove_reference<
                               U>::type &>())>::value &&
              std::is_same<
                  bool,
                  decltype(std::declval<const typename std::remove_reference<
                               U>::type &>() ==
                           std::declval<const typename std::remove_reference<
                               T>::type &>())>::value &&
              std::is_same<
                  bool,
                  decltype(std::declval<const typename std::remove_reference<
                               U>::type &>() !=
                           std::declval<const typename std::remove_reference<
                               T>::type &>())>::value> {};
} // namespace detail

// 与えられた型Tが等値比較可能である場合trueを返す
// C++20のequality_comparable concept互換
template <typename T>
struct is_equality_comparable
    : public detail::is_weakly_equality_comparable_with<T, T> {};

template <typename T>
constexpr bool is_equality_comparable_v = is_equality_comparable<T>::value;

// 与えられた型TとUが等値比較可能である場合trueを返す
// C++20のequality_comparable_with conceptサブセット
// 本来TとUのcommon_reference_withが取れる事を
// 確認しなければならないが、common_reference_withを
// 実装するには力技実装を要するbasic_common_referenceが
// 必要になる為確認していない
template <typename T, typename U>
struct is_equality_comparable_with
    : public std::integral_constant<
          bool, is_equality_comparable<T>::value &&
                    is_equality_comparable<U>::value &&
                    detail::is_weakly_equality_comparable_with<T, U>::value> {};

template <typename T, typename U>
constexpr bool is_equality_comparable_with_v =
    is_equality_comparable_with<T, U>::value;

} // namespace fuzzuf::utils::type_traits
#endif
