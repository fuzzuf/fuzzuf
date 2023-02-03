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
 * @file type_sequence.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_TYPE_SEQUENCE_HPP
#define FUZZUF_INCLUDE_UTILS_TYPE_SEQUENCE_HPP

namespace fuzzuf::utils {
/**
 * @class TypeSequenceT
 * @brief A template type with variable number of template parameter types
 * This is intended to use as tuple for type calculation
 * @tparam T Types
 *
 * example:
 * TypeSequenceT< int, float >
 * The type itself doesn't have any effects. Instead, it is used to pass
 * sequence of type to other meta functions with declaring that the type has no
 * more  meanings than just a sequence of type.
 */
template <typename... T>
struct TypeSequenceT {};
}  // namespace fuzzuf::utils

#endif
