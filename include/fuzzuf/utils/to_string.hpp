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
 * @file to_string.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_TO_STRING_HPP
#define FUZZUF_INCLUDE_UTILS_TO_STRING_HPP
#include <boost/range/iterator_range.hpp>
#include <chrono>
#include <cstddef>
#include <string>
#include <tuple>
#include <utility>

#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/equality_comparable.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include "fuzzuf/utils/void_t.hpp"

namespace fuzzuf::utils {

template <typename... T>
bool toStringADL(std::string &dest, T &&...value);

/*
 * Serialize built-in numeric types
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
 * Apppend indentation to dest
 * @param dest Destination
 * @param indent_count Depth of indentation
 * @param indent String that is used as one level of indentation
 */
void make_indent(std::string &dest, std::size_t indent_count,
                 const std::string &indent);

/**
 * Serialize values that was strong typedef-ed using Boost.Serialization
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
 */
template <typename T>
auto toString(std::string &dest, const T &value) -> std::enable_if_t<
    std::is_void_v<utils::void_t<decltype(toStringADL(
        std::declval<std::string &>(), std::declval<T>().t))>>,
    bool> {
  using underlying_t =
      utils::type_traits::RemoveCvrT<decltype(std::declval<T>().t)>;
  return toStringADL(dest, underlying_t(value));
}

/**
 * Serialize std::chrono durations
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
 * Serialize std::string (simply append to string)
 */
auto toString(std::string &, const std::string &) -> bool;

/**
 * Serialize std::pair
 * @tparam T1 First type
 * @tparam T2 Second type
 * @param dest Destination
 * @param value Value
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
  if (!toStringADL(dest, value.first)) return false;
  dest += ", ";
  if (!toStringADL(dest, value.second)) return false;
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
  if (!toStringADL(dest, std::get<i>(value))) return false;
  if constexpr (i + 1 == size)
    dest += " }";
  else {
    if (!toString<i + 1, size>(dest, value)) return false;
  }
  return true;
}
}  // namespace detail

/**
 * Serialize std::tuple
 * @tparam T Type of elements
 * @param dest Destination
 * @param value Value
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
 * Serialize value of type that satisfies range concept
 * For the case value_type doesn't satisfy equality comparable concept
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
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
    if (!toStringADL(dest, v)) return false;
  }
  dest += " }";
  return true;
}

/**
 * Serialize value of type that satisfies range concept
 * For the case value_type satisfies equality comparable concept
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
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
      if (!toStringADL(dest, v)) return false;
    } else {
      if (*prev == v) {
        dup_count += 1u;
      } else {
        if (dup_count != 1u) {
          dest += " * ";
          if (!toString(dest, dup_count)) return false;
          dest += "times";
          dup_count = 1u;
        }
        dest += ", ";
        if (!toStringADL(dest, v)) return false;
      }
      ++prev;
    }
  }
  if (dup_count != 1u) {
    dest += " * ";
    if (!toString(dest, dup_count)) return false;
    dest += "times";
    dup_count = 1u;
  }
  dest += " }";
  return true;
}

/**
 * Serialize refered value of type that satisifies dereferenceable concept
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
 */
template <typename T>
auto toString(std::string &dest, const T &value) -> std::enable_if_t<
    std::is_void_v<utils::void_t<decltype(toStringADL(
        std::declval<std::string &>(), *std::declval<T>()))>>,
    bool> {
  if (!value) {
    dest += "(null)";
    return true;
  }
  return toStringADL(dest, *value);
}

/**
 * @class ToStringShortReady
 * @brief Meta function that returns true if function ToString( dest, value ) is
 * defined for type T
 * @tparam T Any type
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
 * @brief Meta function that returns true if function ToString( dest, value,
 * indent_depth, indent_str ) is defined for type T
 * @tparam T Any type
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
 * Serialize value without indentation specifier using implementation above or
 * user defined implementation that is available in the rage of ADL
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value)
    -> std::enable_if_t<to_string_short_ready_v<T>, bool> {
  return toString(dest, value);
}

/**
 * Serialize value with indentation specifier using implementation above or user
 * defined implementation that is available in the rage of ADL
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
 * @param indent_count Depth of indentation
 * @param indent String that is used as one level of indentation
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value,
                         std::size_t indent_count, const std::string &indent)
    -> std::enable_if_t<to_string_long_ready_v<T>, bool> {
  return toString(dest, value, indent_count, indent);
}

/**
 * Serialize value without indentation specifier using implementation above or
 * user defined implementation that is available in the rage of ADL For the case
 * only toString with indentation specifier is available This is equivalent to
 * call toString( dest, value, 0, "  " )
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
 */
template <typename T>
auto toStringADLInternal(std::string &dest, const T &value) -> std::enable_if_t<
    !to_string_short_ready_v<T> && to_string_long_ready_v<T>, bool> {
  return toString(dest, value, 0u, "  ");
}

/**
 * Serialize value with indentation specifier using implementation above or user
 * defined implementation that is available in the rage of ADL For the case only
 * toString without indentation specifier is available This insert indent first,
 * then call toString( dest, value )
 * @tparam T Type of value
 * @param dest Destination
 * @param value Value
 * @param indent_count Depth of indentation
 * @param indent String that is used as one level of indentation
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

/**
 * In most case, this is the only function that is expected to be called
 * directly for serialization
 */
template <typename... T>
bool toStringADL(std::string &dest, T &&...value) {
  return toStringADLInternal(dest, std::forward<T>(value)...);
}

}  // namespace fuzzuf::utils
#endif
