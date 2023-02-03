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
 * @file replace_return_type.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_REPLACE_RETURN_TYPE_HPP
#define FUZZUF_INCLUDE_UTILS_REPLACE_RETURN_TYPE_HPP
#include <type_traits>
namespace fuzzuf::utils::type_traits {
/**
 * @class replace_return_type
 * @brief Meta function to return a functin type with same arguments as U but
 * returns T example: replace_return_type_t< int, void( bool ) > This is
 * equivalent to int( bool )
 * @tparam T New return type
 * @tparam U Function type
 *
 */
template <typename T, typename U>
struct replace_return_type {};

template <typename T, typename R, typename... Args>
struct replace_return_type<T, R(Args...)> {
  using type = T(Args...);
};

template <typename T, typename U>
using replace_return_type_t = typename replace_return_type<T, U>::type;
}  // namespace fuzzuf::utils::type_traits

#endif
