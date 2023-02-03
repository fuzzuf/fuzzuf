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
 * @file state_traits.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_TRAITS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_TRAITS_HPP
#include <type_traits>

#include "fuzzuf/utils/check_capability.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * Meta functions to check if the State type has required member functions
 */

FUZZUF_CHECK_CAPABILITY(HasIncrementUseCount1, has_IncrementUseCount1,
                        std::declval<T &>().increment_use_count())

FUZZUF_CHECK_CAPABILITY(HasIncrementUseCount2, has_IncrementUseCount2,
                        std::declval<T &>().IncUseCount())

FUZZUF_CHECK_CAPABILITY(HasGetWord1, has_get_word1, std::declval<T &>().get())

FUZZUF_CHECK_CAPABILITY(HasGetWord2, has_get_word2, std::declval<T &>().GetW())

FUZZUF_CHECK_CAPABILITY(HasHasPositionHint1, has_has_position_hint1,
                        std::declval<T &>().has_position_hint())

FUZZUF_CHECK_CAPABILITY(HasHasPositionHint2, has_has_position_hint2,
                        std::declval<T &>().HasPositionHint())

FUZZUF_CHECK_CAPABILITY(HasGetPositionHint1, has_GetPositionHint1,
                        std::declval<T &>().get_position_hint())

FUZZUF_CHECK_CAPABILITY(HasGetPositionHint2, has_GetPositionHint2,
                        std::declval<T &>().GetPositionHint())

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
