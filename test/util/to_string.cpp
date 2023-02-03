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
#define BOOST_TEST_MODULE util.to_string
#define BOOST_TEST_DYN_LINK
#include "fuzzuf/utils/to_string.hpp"

#include <boost/test/unit_test.hpp>

// whichが見つけてきたteeのパスにコマンドが存在することを確認する
BOOST_AUTO_TEST_CASE(Boolean) {
  std::string serialized;
  std::vector<std::vector<int>> a{{1, 2}, {3}, {}};
  fuzzuf::utils::toString(serialized, a);
  std::string expected = "{ { 1, 2 }, { 3 }, {} }";
  BOOST_CHECK_EQUAL_COLLECTIONS(serialized.begin(), serialized.end(),
                                expected.begin(), expected.end());
}
