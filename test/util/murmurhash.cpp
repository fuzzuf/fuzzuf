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
#define BOOST_TEST_MODULE util.hash
#define BOOST_TEST_DYN_LINK
#include <array>
#include <boost/test/unit_test.hpp>
#include <iostream>

#include "fuzzuf/utils/common.hpp"
#include "random_data.hpp"
BOOST_AUTO_TEST_CASE(UtilMurmurHash32) {
#ifdef __x86_64__
  BOOST_CHECK_EQUAL((fuzzuf::utils::MurmurHash32(
                        random_data1.data(), random_data1.size(), 0xa5b35705)),
                    1150639252);
  BOOST_CHECK_EQUAL((fuzzuf::utils::MurmurHash32(
                        random_data2.data(), random_data2.size(), 0xa5b35705)),
                    1783865212);
  BOOST_CHECK_EQUAL((fuzzuf::utils::MurmurHash32(
                        random_data3.data(), random_data3.size(), 0xa5b35705)),
                    4021282027);
#else
  BOOST_CHECK_EQUAL((fuzzuf::utils::MurmurHash32(
                        random_data1.data(), random_data1.size(), 0xa5b35705)),
                    1260228967);
  BOOST_CHECK_EQUAL((fuzzuf::utils::MurmurHash32(
                        random_data2.data(), random_data2.size(), 0xa5b35705)),
                    665174276);
  BOOST_CHECK_EQUAL((fuzzuf::utils::MurmurHash32(
                        random_data3.data(), random_data3.size(), 0xa5b35705)),
                    2392848746);
#endif
}
