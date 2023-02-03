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
 * @file get_nth.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_GET_NTH_HPP
#define FUZZUF_INCLUDE_UTILS_GET_NTH_HPP
#include <type_traits>
#include <utility>
namespace fuzzuf::utils::type_traits {
/**
 * @class GetNth
 * @brief
 * Meta function to extract i-th type from template parameters or function
 * argument types example: GetNthT< 1, bool( int, float, double, char ) > This
 * is equivalent to float GetNthT< 2, std::tuple< int, float, double, char > >
 * This is equivalent to double
 * @tparam i i-th element is extracted
 * @tparam U A type with template parameters or function type
 */
template <unsigned int i, typename T, typename Enable = void>
struct GetNth {};

template <unsigned int i, template <typename...> typename L, typename Head,
          typename... Tail>
struct GetNth<i, L<Head, Tail...>, std::enable_if_t<i != 0u>>
    : public GetNth<i - 1u, L<Tail...>> {};

template <unsigned int i, template <typename...> typename L, typename Head,
          typename... Tail>
struct GetNth<i, L<Head, Tail...>, std::enable_if_t<i == 0u>> {
  using type = Head;
};

template <unsigned int i, typename R, typename Head, typename... Tail>
struct GetNth<i, R(Head, Tail...), std::enable_if_t<i != 0u>>
    : public GetNth<i - 1u, R(Tail...)> {};

template <unsigned int i, typename R, typename Head, typename... Tail>
struct GetNth<i, R(Head, Tail...), std::enable_if_t<i == 0u>> {
  using type = Head;
};

template <unsigned int i, typename T, T head, T... tail>
struct GetNth<i, std::integer_sequence<T, head, tail...>,
              std::enable_if_t<i != 0u>>
    : public GetNth<i - 1u, std::integer_sequence<T, tail...>> {};

template <unsigned int i, typename T, T head, T... tail>
struct GetNth<i, std::integer_sequence<T, head, tail...>,
              std::enable_if_t<i == 0u>>
    : public std::integral_constant<T, head> {};

template <unsigned int i, typename T>
using GetNthT = typename GetNth<i, T>::type;

template <unsigned int i, typename T>
constexpr auto GetNth_v = GetNth<i, T>::value;
}  // namespace fuzzuf::utils::type_traits
#endif
