/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
#define BOOST_TEST_MODULE util.load_border_edges
#define BOOST_TEST_DYN_LINK
#include <algorithm>
#include <boost/test/unit_test.hpp>
#include "config.h"
#include "fuzzuf/utils/kscheduler/load_border_edges.hpp"

BOOST_AUTO_TEST_CASE(LoadBorderEdges) {
  const auto result = fuzzuf::utils::kscheduler::LoadBorderEdges( TEST_SOURCE_DIR "/util/border_edges" );
  BOOST_CHECK_EQUAL( result.size(), 122 );
  const auto found = std::find_if(
    result.begin(), result.end(),
    []( const auto &v ) -> bool {
      return v.first == 17916 && v.second == 4751;
    }
  );
  BOOST_CHECK( found != result.end() );
}

