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
#define BOOST_TEST_MODULE util.locate_diffs
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/utils/common.hpp"
BOOST_AUTO_TEST_CASE(UtilLocateDiffs1) {
  constexpr std::array<std::uint8_t, 16U> a{0x9f, 0xad, 0xf0, 0xbe, 0x42, 0xec,
                                            0x0,  0xf8, 0xce, 0x87, 0x00, 0xbb,
                                            0xcc, 0xd9, 0x2e, 0x00};
  constexpr std::array<std::uint8_t, 16U> b{0x9f, 0xad, 0xf0, 0xbf, 0x42, 0xec,
                                            0x0,  0xf8, 0xce, 0x87, 0x00, 0xbb,
                                            0xc0, 0xd9, 0x2e, 0x00};
  const auto [first, last] =
      fuzzuf::utils::LocateDiffs(a.data(), b.data(), a.size());
  BOOST_CHECK_EQUAL(first, 3);
  BOOST_CHECK_EQUAL(last, 12);
}

BOOST_AUTO_TEST_CASE(UtilLocateDiffs2) {
  constexpr std::array<std::uint8_t, 16U> a{0x90, 0xad, 0xf0, 0xbe, 0x42, 0xec,
                                            0x0,  0xf8, 0xce, 0x87, 0x00, 0xbb,
                                            0xcc, 0xd9, 0x2e, 0x03};
  constexpr std::array<std::uint8_t, 16U> b{0x9f, 0xad, 0xf0, 0xbe, 0x42, 0xec,
                                            0x0,  0xf8, 0xce, 0x87, 0x00, 0xbb,
                                            0xcc, 0xd9, 0x2e, 0x00};
  const auto [first, last] =
      fuzzuf::utils::LocateDiffs(a.data(), b.data(), a.size());
  BOOST_CHECK_EQUAL(first, 0);
  BOOST_CHECK_EQUAL(last, 15);
}

BOOST_AUTO_TEST_CASE(UtilLocateDiffs3) {
  constexpr std::array<std::uint8_t, 16U> a{0x9f, 0xad, 0xf0, 0xbe, 0x42, 0xec,
                                            0x0,  0xf8, 0xce, 0x87, 0x00, 0xbb,
                                            0xcc, 0xd9, 0x2e, 0x00};
  constexpr std::array<std::uint8_t, 16U> b{0x9f, 0xad, 0xf0, 0xbe, 0x42, 0xec,
                                            0x0,  0xf8, 0xce, 0x87, 0x00, 0xbb,
                                            0xcc, 0xd9, 0x2e, 0x00};
  const auto [first, last] =
      fuzzuf::utils::LocateDiffs(a.data(), b.data(), a.size());
  BOOST_CHECK_EQUAL(first, -1);
  BOOST_CHECK_EQUAL(last, -1);
}
