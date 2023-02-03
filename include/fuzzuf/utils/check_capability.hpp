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
 * @file check_capability.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_CHECK_CAPABILITY_HPP
#define FUZZUF_INCLUDE_UTILS_CHECK_CAPABILITY_HPP
#include <type_traits>

#include "fuzzuf/utils/void_t.hpp"
// 与えられた型Tがexprを評価出来る場合にtrueになるtype_traits <name>を生成する
// 使用例: Tがメンバ変数hogeを持っている場合だけ呼べる関数fugaを作る
// FUZZUF_CHECK_CAPABILITY( has_hoge, std::declval< T >().hoge )
// template< typename T >auto fuga( T ) -> std::enable_if_t< has_hoge_v< T > > {
// ... }
#define FUZZUF_CHECK_CAPABILITY(camel_name, name, expr) \
  template <typename T, typename Enable = void>         \
  struct camel_name : public std::false_type {};        \
  template <typename T>                                 \
  struct camel_name<T, utils::void_t<decltype(expr)>>   \
      : public std::true_type {};                       \
  template <typename T>                                 \
  constexpr bool name##_v = camel_name<T>::value;
#endif
