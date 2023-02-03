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
 * @file minimum_iterator_category.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_MINIMUM_ITERATOR_CATEGORY_HPP
#define FUZZUF_INCLUDE_UTILS_MINIMUM_ITERATOR_CATEGORY_HPP
#include <iterator>
#include <type_traits>
namespace fuzzuf::utils::range {

template <typename T, typename Enable = void>
struct minimum_iterator_category {};
template <template <typename...> typename L, typename Head, typename... Tail>
struct minimum_iterator_category<
    L<Head, Tail...>,
    std::enable_if_t<std::is_convertible_v<
        Head, typename minimum_iterator_category<L<Tail...>>::type>>> {
  using type = typename minimum_iterator_category<L<Tail...>>::type;
};
template <template <typename...> typename L, typename Head, typename... Tail>
struct minimum_iterator_category<
    L<Head, Tail...>,
    std::enable_if_t<
        !std::is_convertible_v<
            Head, typename minimum_iterator_category<L<Tail...>>::type> &&
        std::is_convertible_v<
            typename minimum_iterator_category<L<Tail...>>::type, Head>>> {
  using type = Head;
};
template <template <typename...> typename L>
struct minimum_iterator_category<L<>, void> {
#if __cplusplus >= 202002L
  using type = std::contiguous_iterator_tag;
#else
  using type = std::random_access_iterator_tag;
#endif
};
template <typename T>
using minimum_iterator_category_t = typename minimum_iterator_category<T>::type;

}  // namespace fuzzuf::utils::range

#endif
