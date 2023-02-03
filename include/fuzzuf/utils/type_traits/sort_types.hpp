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
 * @file sort_types.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_SORT_TYPES_HPP
#define FUZZUF_INCLUDE_UTILS_SORT_TYPES_HPP
#include <type_traits>

#include "fuzzuf/utils/type_traits/get_nth.hpp"
#include "fuzzuf/utils/type_traits/insert_nth.hpp"

namespace fuzzuf::utils::type_traits {
/**
 * @class SortTypes
 * @brief
 * Meta function to sort template parameters or function argument types in order
 * specified by Order example: SortTypes< std::integral_sequence< int, 1, 2, 0
 * >, bool( int, float, double ) > This is equivalent to bool( float, double,
 * int ) SortTypes< std::integral_sequence< int, 2, 1, 0 >, std::tuple< int,
 * float, double > > This is equivalent to std::tuple< double, float, int >
 *
 * @tparam Order std::integer_sequence to define order
 * @tparam U A type with template parameters or function type
 */
template <typename Order, typename T>
struct SortTypes {};

template <typename I, I head, I... tail, template <typename...> typename L,
          typename... T>
struct SortTypes<std::integer_sequence<I, head, tail...>, L<T...>> {
  using type = InsertNthT<
      0u, GetNthT<head, L<T...>>,
      typename SortTypes<std::integer_sequence<I, tail...>, L<T...>>::type>;
};
template <typename I, template <typename...> typename L, typename... T>
struct SortTypes<std::integer_sequence<I>, L<T...>> {
  using type = L<>;
};

template <typename I, I head, I... tail, typename R, typename... T>
struct SortTypes<std::integer_sequence<I, head, tail...>, R(T...)> {
  using type = InsertNthT<
      0u, GetNthT<head, R(T...)>,
      typename SortTypes<std::integer_sequence<I, tail...>, R(T...)>::type>;
};
template <typename I, typename R, typename... T>
struct SortTypes<std::integer_sequence<I>, R(T...)> {
  using type = R();
};

template <typename Order, typename T>
using SortTypesT = typename SortTypes<Order, T>::type;
}  // namespace fuzzuf::utils::type_traits

#endif
