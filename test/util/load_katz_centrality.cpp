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
#define BOOST_TEST_MODULE util.load_katz_centrality
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include "config.h"
#include "fuzzuf/utils/kscheduler/load_katz_centrality.hpp"

BOOST_AUTO_TEST_CASE(LoadKatzCentrality) {
  const auto result = fuzzuf::utils::kscheduler::LoadKatzCentrality( TEST_SOURCE_DIR "/util/katz_cent" );
  BOOST_CHECK_EQUAL( result.size(), 132 );
  const auto found = result.find( 28393 );
  BOOST_CHECK( found != result.end() );
  BOOST_CHECK_EQUAL( found->second, 10.0 );
}

