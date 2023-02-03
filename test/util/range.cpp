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
#define BOOST_TEST_MODULE util.range
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <vector>

#include "fuzzuf/utils/filtered_range.hpp"
#include "fuzzuf/utils/nth_range.hpp"
#include "fuzzuf/utils/shared_range.hpp"
#include "fuzzuf/utils/zip_range.hpp"

// shared_rangeしたvectorのiteratorがrandom_access_iteratorの要件を満たす事を確認
BOOST_AUTO_TEST_CASE(SharedRange) {
  using namespace fuzzuf::utils::range::adaptor;
  std::shared_ptr<std::vector<int>> p(new std::vector<int>{1, 2, 3, 4, 5});
  auto sr1 = p | shared;
  auto sr2 = p | shared;
  auto sr3 = sr2;
  BOOST_CHECK((sr1.begin().get() == p->begin()));
  BOOST_CHECK((sr2.begin().get() == p->begin()));
  BOOST_CHECK((sr1.end().get() == p->end()));
  BOOST_CHECK((sr2.end().get() == p->end()));
  BOOST_CHECK_EQUAL(sr1.size(), p->size());
  BOOST_CHECK_EQUAL(sr2.size(), p->size());
  BOOST_CHECK_EQUAL(sr1.empty(), p->empty());
  BOOST_CHECK_EQUAL(sr2.empty(), p->empty());
  p.reset();
  BOOST_CHECK((sr1.begin() == sr2.begin()));
  BOOST_CHECK((sr1.end() == sr2.end()));
  BOOST_CHECK((++sr1.begin() == ++sr2.begin()));
  BOOST_CHECK((--sr1.end() == --sr2.end()));
  BOOST_CHECK((*sr1.begin() == *sr2.begin()));
  BOOST_CHECK((sr1.begin()[2] == sr2.begin()[2]));
  BOOST_CHECK((sr1.begin() == sr3.begin()));
  BOOST_CHECK((sr1.end() == sr3.end()));
}

// zip_range
BOOST_AUTO_TEST_CASE(ZipRange) {
  using namespace fuzzuf::utils::range::adaptor;
  std::vector<int> p1{1, 2, 3, 4, 5};
  std::vector<int> p2{2, 4, 6, 8, 10};
  auto zipped = fuzzuf::utils::range::zip(p1, p2);
  BOOST_CHECK((std::get<0>(zipped.begin().get()) == p1.begin()));
  BOOST_CHECK((std::get<1>(zipped.begin().get()) == p2.begin()));
  BOOST_CHECK((std::get<0>(zipped.end().get()) == p1.end()));
  BOOST_CHECK((std::get<1>(zipped.end().get()) == p2.end()));
  for (const auto &[a, b] : zipped) {
    BOOST_CHECK_EQUAL(a * 2, b);
  }
}

// filtered_range
BOOST_AUTO_TEST_CASE(FilteredRange) {
  using namespace fuzzuf::utils::range::adaptor;
  std::vector<int> data{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<int> expected{1, 3, 5, 7, 9};
  auto filtered_ = data | filtered([](int v) { return v % 2; });
  BOOST_CHECK_EQUAL_COLLECTIONS(filtered_.begin(), filtered_.end(),
                                expected.begin(), expected.end());
}

// nth_range
BOOST_AUTO_TEST_CASE(NthRange) {
  using namespace fuzzuf::utils::range::adaptor;
  std::vector<std::pair<int, int>> data{
      {1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}};
  std::vector<int> expected{1, 3, 5, 7, 9};
  auto nth_ = data | nth<0U>;
  BOOST_CHECK_EQUAL_COLLECTIONS(nth_.begin(), nth_.end(), expected.begin(),
                                expected.end());
}
