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

#include <algorithm>
#include <cassert>
#include <limits>
#include <random>
#include <stdexcept>
#include <type_traits>
#include <utility>


namespace fuzzuf::utils::random {

/* FIXME: Unify the designs of RNG(random number generators) and probability distributions. 
** See the TODO.md.
*/
int RandInt(int lower, int upper);

/* Uniform distribution template for both integral and floating values */
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
 * @brief Choose a random element from C array
 * @param (arr) Array
 * @param (size) Size of array
 * @return Randomly chosen element
 */
template <class T>
T Choose(const T* arr, size_t size) {
  if (size == 0) throw std::out_of_range("Array must not be empty");
  return arr[Random<size_t>(0, size - 1)];
}

/**
 * @fn
 * @brief Choose a random element from vector
 * @param (v) Vector
 * @return Randomly chosen element
 */
template <class T>
T& Choose(std::vector<T>& v) {
  if (v.size() == 0) throw std::out_of_range("Array must not be empty");
  return v[Random<size_t>(0, v.size() - 1)];
}


/* Walker's Alias Method */
template <class T>
class WalkerDiscreteDistribution {
public:
  struct AliasEntry {
    AliasEntry() = delete;
    AliasEntry(size_t val, size_t alias, double prob_of_val)
      : val(val), alias(alias), prob_of_val(prob_of_val) {}

    size_t val;
    size_t alias;
    double prob_of_val;
  };

  WalkerDiscreteDistribution() {};

  /**
   * @fn
   * @brief Construct discrete distribution by C array
   * @param (probs) Array of probabilities (weights)
   * @param (size) Size of array
   */
  WalkerDiscreteDistribution(const T* probs, size_t size) {
    assert (probs != NULL && size != 0);

    double n = static_cast<double>(size);
    double inv_n = 1.0 / n;

    double s = 0.0;
    for (size_t i = 0; i < size; i++) {
      s += static_cast<double>(probs[i]);
    }

    /* Get index-weight pairs */
    std::vector<std::pair<size_t, double>> tmp;
    for (size_t i = 0; i < size; i++) {
      tmp.emplace_back(std::make_pair(i, static_cast<double>(probs[i]) / s));
    }

    while (tmp.size() > 1) {
      /* Descending sort */
      std::sort(tmp.begin(), tmp.end(),
                [](auto a, auto b) {
                  return a.second > b.second;
                });

      /* Take one from small group */
      auto [min_i, min_p] = tmp.back();
      tmp.pop_back();

      /* Take one from big group */
      auto& [max_i, max_p] = tmp[0];
      _entries.emplace_back(min_i, max_i, min_p * n);

      max_p -= inv_n - min_p;
    }

    auto [last_i, last_p] = tmp.back();
    tmp.pop_back();

    /* Last value should always be exactly 1 but we consider precision */
    assert (0.999 < last_p * n && last_p * n < 1.001);

    _entries.emplace_back(last_i, std::numeric_limits<size_t>::max(), 1.0);
  }

  /**
   * @fn
   * @brief Construct discrete distribution by C++ vector
   * @param (probs) Vector of probabilities (weights)
   */
  WalkerDiscreteDistribution(const std::vector<T>& probs)
    : WalkerDiscreteDistribution(probs.data(), probs.size()) {}

  /**
   * @fn
   * @brief 
   * @return Array index chosen by weighted random
   */
  size_t operator() () const {
    size_t index = Random<size_t>(0, _entries.size()-1);
    double coin = Random<double>(0.0, 1.0);
    const AliasEntry& entry = _entries[index];

    if (coin > entry.prob_of_val) {
      return entry.alias;
    }

    return entry.val;
  }

private:
  std::vector<AliasEntry> _entries;
};

} // namespace fuzzuf::utils::random
#endif

