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
#define BOOST_TEST_MODULE algorithms.eclipser.gray_concolic
#define BOOST_TEST_DYN_LINK
#include <config.h>
#include <random>
#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <nlohmann/json.hpp>
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/tests/byte.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/gray_concolic.hpp"

BOOST_AUTO_TEST_CASE(Run) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-threshold";
  options.fork_server = false;
  options.n_spawn = 10;
  fuzzuf::algorithm::eclipser::options::SplitArgs( options );
  fuzzuf::algorithm::eclipser::executor::Initialize( options );
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ) } );
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );

  std::mt19937 rng;

  auto result = fuzzuf::algorithm::eclipser::gray_concolic::Run(
    []( std::string &&m ) { std::cout << m << std::flush; },
    rng,
    options,
    seed
  );
  int new_edge_count = 0u;
  for( const auto &r: result ) {
    if( std::get< 2 >( r ) == fuzzuf::algorithm::eclipser::CoverageGain::NewEdge ) {
      BOOST_CHECK_EQUAL( nlohmann::json( std::get< 0 >( r ) ), nlohmann::json( seed ) );
      BOOST_CHECK_EQUAL( nlohmann::json( std::get< 1 >( r ) ), nlohmann::json( fuzzuf::algorithm::eclipser::Signal::SIGABRT ) );
      ++new_edge_count;
    }
  }
  BOOST_CHECK_EQUAL( new_edge_count, 1 );
}

