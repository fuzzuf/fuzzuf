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
#ifndef FUZZUF_INCLUDE_UTILS_TO_STRING_HPP
#define FUZZUF_INCLUDE_UTILS_TO_STRING_HPP
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/equality_comparable.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include "fuzzuf/utils/void_t.hpp"
#include <boost/range/iterator_range.hpp>
#include <chrono>
#include <cstddef>
#include <string>
#include <tuple>
#include <utility>

namespace fuzzuf::utils {

template <typename... T> bool toStringADL(std::string &dest, T &&...value);

/*
 * 組み込みの数値型を文字列に変換する
 */
auto toString(std::string &dest, bool) -> bool;
auto toString(std::string &dest, unsigned char) -> bool;
auto toString(std::string &dest, signed char) -> bool;
auto toString(std::string &dest, unsigned short) -> bool;
auto toString(std::string &dest, signed short) -> bool;
auto toString(std::string &dest, unsigned int) -> bool;
auto toString(std::string &dest, signed int) -> bool;
auto toString(std::string &dest, unsigned long) -> bool;
auto toString(std::string &dest, signed long) -> bool;
auto toString(std::string &dest, unsigned long long) -> bool;
auto toString(std::string &dest, signed long long) -> bool;
auto toString(std::string &dest, float) -> bool;
auto toString(std::string &dest, double) -> bool;
auto toString(std::string &dest, long double) -> bool;

/**
 * @fn
 * destにインデントを追記する
 * @param dest インデントの書き込み先
 * @param indent_count インデントの深さ
 * @param indent インデントに使う文字列
 */
void make_indent(std::string &dest, std::size_t indent_count,
                 const std::string &indent);

/**
 * @fn
 * Boost.Serializationでstrong typedefされた値を文字列に変換する
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 */
template <typename T>
auto toString(std::string &dest, const T &value) -> std::enable_if_t<
    std::is_void_v<utils::void_t<decltype(
        toStringADL(std::declval<std::string &>(), std::declval<T>().t))>>,
    bool> {
  using underlying_t =
      utils::type_traits::RemoveCvrT<decltype(std::declval<T>().t)>;
  return toStringADL(dest, underlying_t(value));
}

/*
 * chronoの時間を文字列に変換する
 */
auto toString(std::string &, const std::chrono::nanoseconds &) -> bool;
auto toString(std::string &, const std::chrono::microseconds &) -> bool;
auto toString(std::string &, const std::chrono::milliseconds &) -> bool;
auto toString(std::string &, const std::chrono::seconds &) -> bool;
auto toString(std::string &, const std::chrono::minutes &) -> bool;
auto toString(std::string &, const std::chrono::hours &) -> bool;

#if __cplusplus >= 202002L
auto toString(std::string &, const std::chrono::days &) -> bool;
auto toString(std::string &, const std::chrono::weeks &) -> bool;
auto toString(std::string &, const std::chrono::months &) -> bool;
auto toString(std::string &, const std::chrono::years &) -> bool;
#endif

/**
 * @fn
 * 文字列を文字列に追記する
 */
auto toString(std::string &, const std::string &) -> bool;

/**
 * @fn
 * std::pairを文字列に変換する
 * @tparm T1 firstの型
 * @tparm T2 secondの型
 * @param dest 出力先
 * @param value 値
 */
template <typename T1, typename T2>
auto toString(std::string &dest, const std::pair<T1, T2> &value)
    -> std::enable_if_t<
        std::is_same_v<decltype(toStringADL(std::declval<std::string &>(),
                                            std::declval<T1>())),
                       bool> &&
            std::is_same_v<decltype(toStringADL(std::declval<std::string &>(),
                                                std::declval<T2>())),
                           bool>,
        bool> {
  dest += "{ ";
  if (!toStringADL(dest, value.first))
    return false;
  dest += ", ";
  if (!toStringADL(dest, value.second))
    return false;
  dest += " }";
  return true;
}

namespace detail {

template <int i, int size, typename... T>
auto toString(std::string &dest, const std::tuple<T...> &value)
    -> std::enable_if_t<
        std::is_same_v<decltype(toStringADL(
                           std::declval<std::string &>(),
                           std::get<i>(std::declval<std::tuple<T...>>()))),
                       bool> &&
            i != size,
        bool> {
  if constexpr (i == 0)
    dest += "{ ";
  else
    dest += ", ";
  if (!toStringADL(dest, std::get<i>(value)))
    return false;
  if constexpr (i + 1 == size)
    dest += " }";
  else {
    if (!toString<i + 1, size>(dest, value))
      return false;
  }
  return true;
}
} // namespace detail

/**
 * @fn
 * std::tupleを文字列に変換する
 * @tparm T 要素の型
 * @param dest 出力先
 * @param value 値
 */
template <typename... T>
auto toString(std::string &dest, const std::tuple<T...> &value)
    -> std::enable_if_t<
        std::is_same_v<
            decltype(detail::toString<0u, std::tuple_size_v<std::tuple<T...>>>(
                std::declval<std::string &>(),
                std::declval<const std::tuple<T...> &>())),
            bool>,
        bool> {
  return detail::toString<0u, std::tuple_size_v<std::tuple<T...>>>(dest, value);
}

/**
 * @fn
 * rangeの要件を満たす型の値を文字列に変換する
 * 要素の同地比較が不能な場合用
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 */
template <typename T>
auto toString(std::string &dest, const T &value) -> std::enable_if_t<
    !std::is_same_v<utils::type_traits::RemoveCvrT<T>, std::string> &&
        utils::range::is_range_v<T> &&
        !utils::type_traits::is_equality_comparable_v<
            utils::range::RangeValueT<T>>,
    bool> {
  if (utils::range::rangeEmpty(value)) {
    dest += "{}";
    return true;
  }
  dest += "{ ";
  bool first = true;
  for (const auto &v : value) {
    if (first)
      first = false;
    else
      dest += ", ";
    if (!toStringADL(dest, v))
      return false;
  }
  dest += " }";
  return true;
}

/**
 * @fn
 * rangeの要件を満たす型の値を文字列に変換する
 * 要素の同地比較が可能な場合用
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 */
template <typename T>
auto toString(std::string &dest, const T &value) -> std::enable_if_t<
    !std::is_same_v<utils::type_traits::RemoveCvrT<T>, std::string> &&
        utils::range::is_range_v<T> &&
        utils::type_traits::is_equality_comparable_v<
            utils::range::RangeValueT<T>>,
    bool> {
  if (utils::range::rangeEmpty(value)) {
    dest += "{}";
    return true;
  }
  dest += "{ ";
  bool first = true;
  auto prev = value.begin();
  std::size_t dup_count = 1u;
  for (const auto &v : value) {
    if (first) {
      first = false;
      if (!toStringADL(dest, v))
        return false;
    } else {
      if (*prev == v) {
        dup_count += 1u;
      } else {
        if (dup_count != 1u) {
          dest += " * ";
          if (!toString(dest, dup_count))
            return false;
          dest += "times";
          dup_count = 1u;
        }
        dest += ", ";
        if (!toStringADL(dest, v))
          return false;
      }
      ++prev;
    }
  }
  if (dup_count != 1u) {
    dest += " * ";
    if (!toString(dest, dup_count))
      return false;
    dest += "times";
    dup_count = 1u;
  }
  dest += " }";
  return true;
}

/**
 * @fn
 * デリファレンス可能な型を文字列に変換する
 * @tparm T 要素の型
 * @param dest 出力先
 * @param value 値
 */
template <typename T>
auto toString(std::string &dest, const T &value) -> std::enable_if_t<
    std::is_void_v<utils::void_t<decltype(
        toStringADL(std::declval<std::string &>(), *std::declval<T>()))>>,
    bool> {
  if (!value) {
    dest += "(null)";
    return true;
  }
  return toStringADL(dest, *value);
}

/**
 * @class ToStringShortReady
 * @brief インデント指定なしのtoStringが定義されている型の場合trueが返る
 * @tparm T 任意型
 */
template <typename T, typename Enable = void>
struct ToStringShortReady : public std::false_type {};
template <typename T>
struct ToStringShortReady<
    T, std::enable_if_t<
           std::is_same_v<decltype(toString(std::declval<std::string &>(),
                                            std::declval<const T &>())),
                          bool>>> : public std::true_type {};
template <typename T>
constexpr bool to_string_short_ready_v = ToStringShortReady<T>::value;

/**
 * @class ToStringLongReady
 * @brief インデント指定付きのtoStringが定義されている型の場合trueが返る
 * @tparm T 任意型
 */
template <typename T, typename Enable = void>
struct ToStringLongReady : public std::false_type {};
template <typename T>
struct ToStringLongReady<
    T,
    std::enable_if_t<std::is_same_v<
        decltype(toString(
            std::declval<std::string &>(), std::declval<const T &>(),
            std::declval<std::size_t>(), std::declval<const std::string &>())),
        bool>>> : public std::true_type {};
template <typename T>
constexpr bool to_string_long_ready_v = ToStringLongReady<T>::value;

/**
 * @fn
 * ADLを含めてインデント指定無しのtoStringが利用可能な場合、それを使って値を文字列に変換する
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value)
    -> std::enable_if_t<to_string_short_ready_v<T>, bool> {
  return toString(dest, value);
}

/**
 * @fn
 * ADLを含めてインデント指定付きのtoStringが利用可能な場合、それを使って値を文字列に変換する
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 * @param indent_count インデントの深さ
 * @param indent インデントに使う文字列
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value,
                         std::size_t indent_count, const std::string &indent)
    -> std::enable_if_t<to_string_long_ready_v<T>, bool> {
  return toString(dest, value, indent_count, indent);
}

/**
 * @fn
 * インデント指定無しのtoStringを要求されているが、ADLを含めてインデント指定付きのtoStringしか見つからない場合、"
 * "を0段の状態でインデント付きのtoStringを使って文字列に変換する
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value) -> std::enable_if_t<
    !to_string_short_ready_v<T> && to_string_long_ready_v<T>, bool> {
  return toString(dest, value, 0u, "  ");
}

/**
 * @fn
 * インデント指定付きのtoStringを要求されているが、ADLを含めてインデント指定無しのtoStringしか見つからない場合、指定されたインデントを挿入してからインデント指定無しのtoStringを使って文字列に変換する
 * @tparm T 値の型
 * @param dest 出力先
 * @param value 値
 * @param indent_count インデントの深さ
 * @param indent インデントに使う文字列
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value,
                         std::size_t indent_count, const std::string &indent)
    -> std::enable_if_t<
        to_string_short_ready_v<T> && !to_string_long_ready_v<T>, bool> {
  make_indent(dest, indent_count, indent);
  auto result = toString(dest, value);
  dest += '\n';
  return result;
}

template <typename... T> bool toStringADL(std::string &dest, T &&...value) {
  return toStringADLInternal(dest, std::forward<T>(value)...);
}

} // namespace fuzzuf::utils
#endif
