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
 * @file void_t.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_VOID_T_HPP
#define FUZZUF_INCLUDE_UTILS_VOID_T_HPP

#ifndef __clang__
#include <type_traits>
#endif

namespace fuzzuf::utils {
/**
 * clang has problem described in C++ core issue 1558 even if -std=c++17 or
 * higher is specified. As the result, void_t must be re-defined with workaround
 * to avoid this problem.
 * http://www.open-std.org/jtc1/sc22/wg21/docs/cwg_defects.html#1558
 */
#ifdef __clang__
template <typename... T>
struct voider {
  using type = void;
};
template <typename... T>
using void_t = typename voider<T...>::type;
#else
template <typename... T>
using void_t = std::void_t<T...>;
#endif
}  // namespace fuzzuf::utils

#endif
