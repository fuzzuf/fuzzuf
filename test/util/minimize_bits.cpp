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
#define BOOST_TEST_MODULE util.minimize_bits
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <vector>

#include "fuzzuf/utils/common.hpp"
BOOST_AUTO_TEST_CASE(UtilMinimizeBits) {
  constexpr std::array<std::uint8_t, 64U> data{
      0x9f, 0xad, 0xf0, 0xbf, 0x42, 0xec, 0x0,  0xf8, 0xce, 0x87, 0x00,
      0xbb, 0xc0, 0xd9, 0x2e, 0x00, 0x12, 0x4d, 0xfa, 0x17, 0x4,  0x41,
      0x1f, 0xa,  0x00, 0x00, 0x3b, 0x3c, 0x00, 0x8a, 0x00, 0xad, 0xce,
      0xc3, 0xd1, 0x00, 0x00, 0xe0, 0x21, 0x00, 0x61, 0xc7, 0x57, 0xd6,
      0x9e, 0x00, 0x85, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x60, 0xfb, 0xd6, 0x5b, 0xd8, 0x70, 0xc0, 0xec};
  namespace tt = boost::test_tools;
  std::vector<std::uint8_t> result(data.size() / 8, 0);
  const std::vector<std::uint8_t> expected{0xbf, 0x7b, 0xff, 0xac,
                                           0x67, 0xdf, 0x0,  0xff};
  fuzzuf::utils::MinimizeBits(result.data(), data.data(), data.size());
  for (auto v : result)
    std::cout << std::hex << "0x" << uint32_t(v) << ", " << std::flush;
  BOOST_TEST((result == expected), tt::per_element());
}
