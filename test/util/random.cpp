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
#define BOOST_TEST_MODULE util.random
#define BOOST_TEST_DYN_LINK

#include "fuzzuf/utils/random.hpp"

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <future>
#include <numeric>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#define Z_SCORE(N, M, P) ((M - N * P) / std::sqrt(N * P * (1 - P)))

using namespace fuzzuf::utils::random;

BOOST_AUTO_TEST_CASE(TestRandomAndChoose) {
  std::vector<int> v1{10, 11, 12, 13, 14, 15, 16, 17};
  const int v2[] = {10, 11, 12, 13, 14, 15, 16, 17};
  std::vector<double> v3{3.14};
  std::vector<int> v4{};

  for (size_t i = 0; i < 10000; i++) {
    int r1 = Random<int>(0, 10);
    char r2 = Random<char>(-100, 100);
    int r3 = Choose<int>(v1);
    int r4 = Choose<int>(v2, 8);
    double r5 = Choose<double>(v3);
    BOOST_CHECK(0 <= r1 && r1 <= 10);
    BOOST_CHECK(-100 <= r2 && r2 <= 100);
    BOOST_CHECK(10 <= r3 && r3 <= 17);
    BOOST_CHECK(10 <= r4 && r4 <= 17);
    BOOST_CHECK(r5 == 3.14);
  }

  BOOST_CHECK_THROW(Choose<int>(v4), std::out_of_range);
}

BOOST_AUTO_TEST_CASE(TestWalkerDiscreteDistributionSimple) {
  constexpr double Z = 3.32;       // alpha=0.001, Z_{0.0005} (0.1% error)
  constexpr size_t iter = 500000;  // large enough tests

  /* Get random probabilities */
  size_t len = Random<size_t>(3, 9);
  std::vector<double> base;
  for (size_t i = 0; i < len; i++) {
    base.push_back(Random<double>(0.0, 1000.0));
  }

  /* Normalize */
  double sum = std::accumulate(base.begin(), base.end(), 0.0);
  for (double& v : base) {
    v /= sum;
  }

  WalkerDiscreteDistribution<double> s(base);
  std::vector<size_t> res(len);

  for (size_t i = 0; i < iter; i++) {
    size_t index = s();
    BOOST_CHECK(index < len);
    res[index]++;
  }

  /* Run statistical test for each result */
  for (size_t i = 0; i < len; i++) {
    const double z = Z_SCORE(iter, res[i], base[i] / 1.0);
    if (std::isnan(z)) {
      /* sqrt(V) ~ 0.0 case */
      BOOST_CHECK(res[i] == 0);
    } else {
      BOOST_CHECK(std::abs(z) < Z);
    }
  }

  /* Test statistical test */
  res[0] += iter / (len * 10);
  BOOST_CHECK(std::abs(Z_SCORE(iter, res[0], base[0] / 1.0)) >= Z);
}

BOOST_AUTO_TEST_CASE(TestWalkerDiscreteDistributionBiased) {
  constexpr double Z = 3.32;       // alpha=0.001, Z_{0.0005} (0.1% error)
  constexpr size_t iter = 100000;  // smaller than simple test

  /* 1. Test biased weights */
  std::vector<double> w1{1000.0, 0.0, 0.0, 100.0, 100.0};
  double sum1 = std::accumulate(w1.begin(), w1.end(), 0);
  WalkerDiscreteDistribution<double> s1(w1);
  std::vector<size_t> res1(w1.size());
  for (size_t i = 0; i < iter; i++) {
    size_t index = s1();
    BOOST_CHECK(index < w1.size());
    res1[index]++;
  }

  /* Run statistical test for each result */
  for (size_t i = 0; i < w1.size(); i++) {
    const double z = Z_SCORE(iter, res1[i], w1[i] / sum1);
    if (std::isnan(z)) {
      /* sqrt(V) ~ 0.0 case */
      BOOST_CHECK(res1[i] == 0);
    } else {
      BOOST_CHECK(std::abs(z) < Z);
    }
  }

  /* Test statistical test */
  res1[3] += iter / (w1.size() * 10);
  BOOST_CHECK(std::abs(Z_SCORE(iter, res1[3], w1[3] / sum1)) >= Z);

  /* 2. Test invalid weights */
  // empty weight
  std::vector<int> w2{};
  BOOST_CHECK_THROW(WalkerDiscreteDistribution<int> s2(w2), std::out_of_range);
  // negative weight
  std::vector<int> w3{314, -1592, 0, 1};
  BOOST_CHECK_THROW(WalkerDiscreteDistribution<int> s3(w3), std::range_error);
  // NaN weight
  std::vector<float> w4{3.14, 15.92, std::nanf("")};
  BOOST_CHECK_THROW(WalkerDiscreteDistribution<float> s4(w4), std::range_error);
  // zero weights
  std::vector<char> w5{0, 0, 0};
  BOOST_CHECK_THROW(WalkerDiscreteDistribution<char> s5(w5), std::range_error);
  // infinity sum
  std::vector<double> w6{std::numeric_limits<double>::max(),
                         std::numeric_limits<double>::max()};
  BOOST_CHECK_THROW(WalkerDiscreteDistribution<double> s6(w6),
                    std::range_error);

  /* Test small number of big weights */
  std::vector<double> w7{1.0, std::numeric_limits<double>::max()};
  WalkerDiscreteDistribution<double> s7(w7);
  for (size_t i = 0; i < iter; i++) {
    BOOST_CHECK_EQUAL(s7(), 1);
  }

  /* Test array */
  std::array<float, 3> w8{0.000001, 0.000002, 0.000003};
  float sum8 = std::accumulate(w8.begin(), w8.end(), 0.0);
  WalkerDiscreteDistribution<float> s8(w8.cbegin(), w8.cend());
  std::vector<size_t> res8(w8.size());
  for (size_t i = 0; i < iter; i++) {
    size_t index = s8();
    BOOST_CHECK(index < w8.size());
    res8[index]++;
  }
  for (size_t i = 0; i < w8.size(); i++) {
    const double p = w8[i] / sum8;
    const double E = iter * p;
    const double V = iter * (1 - p);
    const double z = (res8[i] - E) / std::sqrt(V);
    BOOST_CHECK(std::abs(z) < Z);
  }
}
