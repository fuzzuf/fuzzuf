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
 * @file random_traits.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_RANDOM_TRAITS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_RANDOM_TRAITS_HPP
#include <random>
#include <type_traits>

#include "fuzzuf/utils/check_capability.hpp"

namespace fuzzuf::algorithm::libfuzzer {

FUZZUF_CHECK_CAPABILITY(IsStdDistribution, is_std_distribution,
                        std::declval<T &>()(std::declval<std::minstd_rand &>()))

template <typename T>
struct IsPiecewiseConstantDistribution : public std::false_type {};
template <typename... T>
struct IsPiecewiseConstantDistribution<
    std::piecewise_constant_distribution<T...>> : public std::true_type {};
template <typename T>
constexpr bool is_piecewise_constant_distribution_v =
    IsPiecewiseConstantDistribution<T>::value;

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
