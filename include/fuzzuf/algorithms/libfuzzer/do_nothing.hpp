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
 * @file do_nothing.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_DO_NOTHING_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_DO_NOTHING_HPP
namespace fuzzuf::algorithm::libfuzzer {

/**
 * A function accepting any arguments and does nothing.
 */
template <typename... Args>
void DoNothing(Args &&...) {}

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
