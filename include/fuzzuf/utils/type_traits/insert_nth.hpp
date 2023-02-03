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
 * @file insert_nth.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_INSERT_NTH_HPP
#define FUZZUF_INCLUDE_UTILS_INSERT_NTH_HPP
#include <type_traits>
#include <utility>
namespace fuzzuf::utils::type_traits {

namespace detail {
template <unsigned int i, typename T, typename Prev, typename Next,
          typename Enable = void>
struct InsertNth {};

template <unsigned int i, typename T, template <typename...> typename L,
          typename... Prev, typename Head, typename... Tail>
struct InsertNth<i, T, L<Prev...>, L<Head, Tail...>, std::enable_if_t<i != 0u>>
    : public InsertNth<i - 1u, T, L<Prev..., Head>, L<Tail...>> {};

template <unsigned int i, typename T, template <typename...> typename L,
          typename... Prev, typename... Next>
struct InsertNth<i, T, L<Prev...>, L<Next...>, std::enable_if_t<i == 0u>> {
  using type = L<Prev..., T, Next...>;
};

template <unsigned int i, typename T, typename R, typename... Prev,
          typename Head, typename... Tail>
struct InsertNth<i, T, R(Prev...), R(Head, Tail...), std::enable_if_t<i != 0u>>
    : public InsertNth<i - 1u, T, R(Prev..., Head), R(Tail...)> {};

template <unsigned int i, typename T, typename R, typename... Prev,
          typename... Next>
struct InsertNth<i, T, R(Prev...), R(Next...), std::enable_if_t<i == 0u>> {
  using type = R(Prev..., T, Next...);
};

template <unsigned int i, typename T, T... values, T... prev, T head, T... tail>
struct InsertNth<
    i, std::integer_sequence<T, values...>, std::integer_sequence<T, prev...>,
    std::integer_sequence<T, head, tail...>, std::enable_if_t<i != 0u>>
    : public InsertNth<i - 1u, std::integer_sequence<T, values...>,
                       std::integer_sequence<T, prev..., head>,
                       std::integer_sequence<T, tail...>> {};

template <unsigned int i, typename T, T... values, T... prev, T... next>
struct InsertNth<i, std::integer_sequence<T, values...>,
                 std::integer_sequence<T, prev...>,
                 std::integer_sequence<T, next...>, std::enable_if_t<i == 0u>> {
  using type = std::integer_sequence<T, prev..., values..., next...>;
};

}  // namespace detail

/**
 * @class InsertNth
 * @brief
 * Meta function to Insert T before i-th element of template parameters or
 * function argument types example: InsertNthT< 1, std::string, bool( int,
 * float, double, char ) > This is equivalent to bool( int, std::string, float,
 * double, char ) InsertNthT< 2, std::string, std::tuple< int, float, double,
 * char > > This is equivalent to std::tuple< int, float, std::string, double,
 * char >
 * @tparam i Insert before i-th element
 * @tparam T Insert this type
 * @tparam U A type with template parameters or function type
 */
template <unsigned int i, typename T, typename U>
struct InsertNth {};
template <unsigned int i, typename T, template <typename...> typename L,
          typename... U>
struct InsertNth<i, T, L<U...>> : public detail::InsertNth<i, T, L<>, L<U...>> {
};

template <unsigned int i, typename T, typename R, typename... U>
struct InsertNth<i, T, R(U...)> : public detail::InsertNth<i, T, R(), R(U...)> {
};

template <unsigned int i, typename T, T... values, T... u>
struct InsertNth<i, std::integer_sequence<T, values...>,
                 std::integer_sequence<T, u...>>
    : public detail::InsertNth<i, std::integer_sequence<T, values...>,
                               std::integer_sequence<T>,
                               std::integer_sequence<T, u...>> {};

template <unsigned int i, typename T, typename U>
using InsertNthT = typename InsertNth<i, T, U>::type;
}  // namespace fuzzuf::utils::type_traits
#endif
