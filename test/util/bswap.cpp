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
#define BOOST_TEST_MODULE util.bswap
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/bswap.hpp"

#include <boost/test/unit_test.hpp>
#include <cstdint>
// エンディアン変換
BOOST_AUTO_TEST_CASE(Bswap) {
  BOOST_CHECK_EQUAL(fuzzuf::utils::bswap<std::uint8_t>()(0x12U), 0x12U);
  BOOST_CHECK_EQUAL(fuzzuf::utils::bswap<std::uint16_t>()(0x1234U), 0x3412U);
  BOOST_CHECK_EQUAL(fuzzuf::utils::bswap<std::uint32_t>()(0x12345678U),
                    0x78563412U);
  BOOST_CHECK_EQUAL(fuzzuf::utils::bswap<std::uint64_t>()(0x1234567891234567U),
                    0x6745239178563412U);
}
