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
#ifndef FUZZUF_INCLUDE_UTILS_TYPE_SEQUENCE_HPP
#define FUZZUF_INCLUDE_UTILS_TYPE_SEQUENCE_HPP

namespace fuzzuf::utils {
/**
 * @class TypeSequenceT
 * @brief 任意の数の型を並べる事ができる型
 * 型計算をする際に複数の型のタプルとして使う
 * @tparm T 型
 *
 * 例:
 * TypeSequenceT< int, float >
 * これ自体が何かの効果を持つわけではなく、型の列をテンプレート引数で要求している箇所に対して「型の列を渡したい以上の意味はない」事を明示しながら型の列を渡すのに使う
 */
template <typename... T> struct TypeSequenceT {};
} // namespace fuzzuf::utils

#endif
