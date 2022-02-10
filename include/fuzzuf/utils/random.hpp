/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file random.hpp
 * @brief Generate random numbers
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_UTILS_RANDOM_HPP
#define FUZZUF_INCLUDE_UTILS_RANDOM_HPP

#include <algorithm>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>
#include <type_traits>
#include <utility>


namespace fuzzuf::utils::random {

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
  if (size == 0)
    throw std::out_of_range("Array must not be empty");

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
  if (v.size() == 0)
    throw std::out_of_range("Array must not be empty");

  return v[Random<size_t>(0, v.size() - 1)];
}

/* Walker's Alias Method */
template <class T>
class WalkerDiscreteDistribution {
public:
  WalkerDiscreteDistribution() {};

  /**
   * @fn
   * @brief Construct discrete distribution
   * @param (probs) Array of probabilities (weights)
   * @param (size) Size of array
   */
  WalkerDiscreteDistribution(const std::vector<T>& probs) {
    if (probs.size() == 0)
      throw std::out_of_range("Array must not be empty");

    /* Check and cast weight */
    _threshold.reserve(probs.size());
    for (const T p: probs) {
      if (static_cast<double>(p) < 0.0 || std::isnan(static_cast<double>(p)))
        throw std::range_error("Weight must not be negative or NaN");

      _threshold.push_back(static_cast<double>(p));
    }

    /* Calculate sum of weights */
    const double n = static_cast<double>(_threshold.size());
    double sum = std::accumulate(_threshold.begin(), _threshold.end(), 0.0);

    if (sum == std::numeric_limits<double>::infinity())
      throw std::range_error("Sum of weights must not be inifinity");
    else if (sum <= 0.0)
      throw std::range_error("Sum of weights must be positive");

    /* Normalize weights so that average becomes 1 */
    for (double& p: _threshold) {
      p = (p / sum) * n;
    }

    /* Prepare index */
    _index.resize(_threshold.size());
    std::iota(_index.begin(), _index.end(), 0);

    /* Split weights into two groups */
    std::vector<size_t> small, large;
    size_t i = 0;
    for (double p: _threshold) {
      if (p < 1.0) {
        small.push_back(i++);
      } else {
        large.push_back(i++);
      }
    }

    while (!small.empty() && !large.empty()) {
      size_t j = small.back();
      small.pop_back();
      size_t k = large.back();

      /* j-th entry has j-th and k-th weights */
      _index[j] = k;

      /* Fill remaining region by k-th weights */
      _threshold[k] -= (1.0 - _threshold[j]);

      if (_threshold[k] < 1.0) {
        /* If k-th weight gets smaller than average, put it into small group */
        small.push_back(k);
        large.pop_back();
      }
    }
  }

  /**
   * @fn
   * @brief Randomly choose an index
   * @return Array index chosen by weighted random
   */
  size_t operator() () const {
    size_t i = Random<size_t>(0, _index.size() - 1);

    if (_threshold[i] > Random<double>(0.0, 1.0)) {
      return i;
    } else {
      return _index[i];
    }
  }

private:
  std::vector<size_t> _index;
  std::vector<double> _threshold;
};

} // namespace fuzzuf::utils::random
#endif

