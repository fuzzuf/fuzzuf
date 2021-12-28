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
#ifndef FUZZUF_INCLUDE_UTILS_ERASE_NTH_HPP
#define FUZZUF_INCLUDE_UTILS_ERASE_NTH_HPP
#include <type_traits>
#include <utility>
namespace fuzzuf::utils::type_traits {

namespace detail {
template <unsigned int i, typename Prev, typename Next, typename Enable = void>
struct erase_nth {};

template <unsigned int i, template <typename...> typename L, typename... Prev,
          typename Head, typename... Tail>
struct erase_nth<i, L<Prev...>, L<Head, Tail...>, std::enable_if_t<i != 0u>>
    : public erase_nth<i - 1u, L<Prev..., Head>, L<Tail...>> {};

template <unsigned int i, template <typename...> typename L, typename... Prev,
          typename Head, typename... Tail>
struct erase_nth<i, L<Prev...>, L<Head, Tail...>, std::enable_if_t<i == 0u>> {
  using type = L<Prev..., Tail...>;
};

template <unsigned int i, typename R, typename... Prev, typename Head,
          typename... Tail>
struct erase_nth<i, R(Prev...), R(Head, Tail...), std::enable_if_t<i != 0u>>
    : public erase_nth<i - 1u, R(Prev..., Head), R(Tail...)> {};

template <unsigned int i, typename R, typename... Prev, typename Head,
          typename... Tail>
struct erase_nth<i, R(Prev...), R(Head, Tail...), std::enable_if_t<i == 0u>> {
  using type = R(Prev..., Tail...);
};

template <unsigned int i, typename T, T... prev, T head, T... tail>
struct erase_nth<i, std::integer_sequence<T, prev...>,
                 std::integer_sequence<T, head, tail...>,
                 std::enable_if_t<i != 0u>>
    : public erase_nth<i - 1u, std::integer_sequence<T, prev..., head>,
                       std::integer_sequence<T, tail...>> {};

template <unsigned int i, typename T, T... prev, T head, T... tail>
struct erase_nth<i, std::integer_sequence<T, prev...>,
                 std::integer_sequence<T, head, tail...>,
                 std::enable_if_t<i == 0u>> {
  using type = std::integer_sequence<T, prev..., tail...>;
};
} // namespace detail

/*
 * @class erase_nth
 * @brief
 * 型Uのテンプレート引数や関数の引数からi番目の要素を削除した型を返すメタ関数
 * 例:
 * erase_nth_t< 1, bool( int, float, double, char ) >
 * これは bool( int, double, char )と同義
 * erase_nth_t< 2, std::tuple< int, float, double, char > >
 * これは std::tuple< int, float, char >と同義
 * @tparm i i番目の要素を削除する
 * @tparm U テンプレート引数を持つ型または関数の型
 *
 */
template <unsigned int i, typename U> struct erase_nth {};
template <unsigned int i, template <typename...> typename L, typename... U>
struct erase_nth<i, L<U...>> : public detail::erase_nth<i, L<>, L<U...>> {};
template <unsigned int i, typename R, typename... U>
struct erase_nth<i, R(U...)> : public detail::erase_nth<i, R(), R(U...)> {};

template <unsigned int i, typename T, T... u>
struct erase_nth<i, std::integer_sequence<T, u...>>
    : public detail::erase_nth<i, std::integer_sequence<T>,
                               std::integer_sequence<T, u...>> {};

template <unsigned int i, typename T>
using erase_nth_t = typename erase_nth<i, T>::type;
} // namespace fuzzuf::utils::type_traits
#endif
