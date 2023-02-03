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
#define BOOST_TEST_MODULE util.not_random
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/not_random.hpp"

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <limits>
// 固定値が返る乱数生成器
BOOST_AUTO_TEST_CASE(Fixed) {
  fuzzuf::utils::not_random::fixed<uint32_t> a;
  BOOST_CHECK_EQUAL(a(), 0U);
  BOOST_CHECK_EQUAL(a(), 0U);
  a.seed(3U);
  BOOST_CHECK_EQUAL(a(), 3U);
  BOOST_CHECK_EQUAL(a(), 3U);
  fuzzuf::utils::not_random::fixed<uint32_t> b(5U);
  BOOST_CHECK_EQUAL(b(), 5U);
  BOOST_CHECK_EQUAL(b(), 5U);
  BOOST_CHECK_EQUAL(b.min(), std::numeric_limits<uint32_t>::min());
  BOOST_CHECK_EQUAL(b.max(), std::numeric_limits<uint32_t>::max());
}

// インクリメンタルな値が返る乱数生成器
BOOST_AUTO_TEST_CASE(Sequential) {
  fuzzuf::utils::not_random::Sequential<uint32_t> a;
  BOOST_CHECK_EQUAL(a(), 0U);
  BOOST_CHECK_EQUAL(a(), 1U);
  a.seed(3U);
  BOOST_CHECK_EQUAL(a(), 3U);
  BOOST_CHECK_EQUAL(a(), 4U);
  fuzzuf::utils::not_random::Sequential<uint32_t> b(5U);
  BOOST_CHECK_EQUAL(b(), 5U);
  BOOST_CHECK_EQUAL(b(), 6U);
  BOOST_CHECK_EQUAL(b.min(), std::numeric_limits<uint32_t>::min());
  BOOST_CHECK_EQUAL(b.max(), std::numeric_limits<uint32_t>::max());
}
