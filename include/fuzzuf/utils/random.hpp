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
/**
 * @file Random.hpp
 * @brief Generate random numbers
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_UTILS_RANDOM_HPP
#define FUZZUF_INCLUDE_UTILS_RANDOM_HPP
#include <limits>
#include <random>
#include <type_traits>

namespace fuzzuf::utils::random {

template<class T>
using uniform_distribution = typename std::conditional<
  std::is_floating_point<T>::value, std::uniform_real_distribution<T>,
  typename std::conditional<
    std::is_integral<T>::value, std::uniform_int_distribution<T>,
    void
  >::type
>::type;

namespace {
std::random_device rd;
std::default_random_engine eng(rd());
}

/* FIXME: Unify the designs of RNG(random number generators) and probability distributions. 
** See the TODO.md.
*/
int RandInt(int lower, int upper);

/**
 * @fn
 * @brief Get a random value in [lower, upper]
 * @param (lower) Lower bound
 * @param (upper) Upper bound
 * @return Random value
 */
template <class T>
T Random(T lower, T upper) {
  uniform_distribution<T> dist(lower, upper);
  return dist(eng);
}

/**
 * @fn
 * @brief Get a random value
 * @return Random value
 */
template <class T>
T Random() {
  uniform_distribution<T> dist(std::numeric_limits<T>::min(),
                               std::numeric_limits<T>::max());
  return dist(eng);
}

/**
 * @fn
 * @brief Choose a random element from vector
 * @param (v) Vector
 * @return Randomly chosen element
 */
template <class T>
T Choose(std::vector<T> v) {
  assert (v.size() > 0);
  return v[Random<size_t>(0, v.size() - 1)];
}
}
#endif

