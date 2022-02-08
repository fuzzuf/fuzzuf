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
#define BOOST_TEST_MODULE nautilus.context
#define BOOST_TEST_DYN_LINK

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <numeric>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/utils/random.hpp"


using namespace fuzzuf::algorithms::nautilus::grammartec;

BOOST_AUTO_TEST_CASE(NautilusGrammartecLoadedDice) {
  /* Get random probabilities */
  size_t len = fuzzuf::utils::random::Random<size_t>(3, 9);
  std::vector<double> base;
  for (size_t i = 0; i < len; i++) {
    base.push_back(fuzzuf::utils::random::Random<double>(0.0, 1.0));
  }

  /* Normalize */
  double sum = std::accumulate(base.begin(), base.end(), 0.0);
  for (double& v: base) {
    v /= sum;
  }

  LoadedDiceSampler s(base);
  std::vector<size_t> res;
  res.resize(len);
  std::fill(res.begin(), res.end(), 0);

  size_t iter = 1000000; // large enough
  for (size_t i = 0; i < iter; i++) {
    res[s.Sample()] += 1;
  }

  std::vector<double> res_p;
  for (size_t f: res) {
    res_p.push_back(static_cast<double>(f) / static_cast<double>(iter));
  }

  for (size_t i = 0; i < len; i++) {
    BOOST_CHECK(base[i] * 0.99 < res_p[i] && base[i] * 1.01 > res_p[i]);
  }
}
