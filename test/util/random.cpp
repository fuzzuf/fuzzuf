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
#define BOOST_TEST_MODULE nautilus.dice
#define BOOST_TEST_DYN_LINK

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <numeric>
#include <stdexcept>
#include <vector>
#include "fuzzuf/utils/random.hpp"


using namespace fuzzuf::utils::random;

BOOST_AUTO_TEST_CASE(TestRandomAndChoose) {
  std::vector<int> v1 = {10, 11, 12, 13, 14, 15, 16, 17};
  const int v2[] = {10, 11, 12, 13, 14, 15, 16, 17};
  std::vector<double> v3 = {3.14};
  std::vector<int> v4 = {};

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

  bool exception_thrown = false;
  try {
    int r6 = Choose<int>(v4);
    std::cerr << "Something chosen from an empty vector: " << r6 << std::endl;
  } catch(const std::out_of_range&) {
    exception_thrown = true;
  }
  BOOST_CHECK(exception_thrown);
}

BOOST_AUTO_TEST_CASE(TestChoose) {
  
}

BOOST_AUTO_TEST_CASE(TestWalkerDiscreteDistribution) {
  /* Get random probabilities */
  size_t len = Random<size_t>(3, 9);
  std::vector<double> base;
  for (size_t i = 0; i < len; i++) {
    base.push_back(Random<double>(0.0, 1.0));
  }

  /* Normalize */
  double sum = std::accumulate(base.begin(), base.end(), 0.0);
  for (double& v: base) {
    v /= sum;
  }

  WalkerDiscreteDistribution<double> s(base);
  std::vector<size_t> res;
  res.resize(len);
  std::fill(res.begin(), res.end(), 0);

  size_t iter = 1000000; // large enough
  for (size_t i = 0; i < iter; i++) {
    res[s()] += 1;
  }

  std::vector<double> res_p;
  for (size_t f: res) {
    res_p.push_back(static_cast<double>(f) / static_cast<double>(iter));
  }

  for (size_t i = 0; i < len; i++) {
    BOOST_CHECK(base[i] * 0.99 < res_p[i] && base[i] * 1.01 > res_p[i]);
  }
}
