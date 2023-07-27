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
#define BOOST_TEST_MODULE algorithms.eclipser.fuzz_monoton
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
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/tests/byte.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"
#include "fuzzuf/algorithms/eclipser/fuzz/fuzz.hpp"
#include "fuzzuf/algorithms/eclipser/fuzz/test_case.hpp"
#include "fuzzuf/algorithms/eclipser/fuzz/scheduler.hpp"

BOOST_AUTO_TEST_CASE(Run) {
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  auto* const raw_dirname = mkdtemp(root_dir_template.data());
  BOOST_CHECK(raw_dirname != nullptr);
  auto root_dir = fs::path(raw_dirname);
  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  BOOST_CHECK_EQUAL(fs::create_directory(output_dir), true);
  //FUZZUF_STANDARD_TEST_DIRS
  
  fs::current_path( output_dir );

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 2;
  options.sync_dir = output_dir.string();
  options.out_dir = ( output_dir / "eclipser" ).string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-monoton";
  options.fork_server = false;
  options.n_spawn = 10;
  options.fuzz_source = fuzzuf::algorithm::eclipser::FileInput{ "input" };
  options.arg = "input";
  fuzzuf::algorithm::eclipser::executor::Initialize( options );
  fuzzuf::algorithm::eclipser::test_case::Initialize( options.out_dir );
  fuzzuf::algorithm::eclipser::scheduler::Initialize();

  std::mt19937 rng;

  BOOST_TEST_CHECKPOINT( "begin fuzz" );
  fuzzuf::algorithm::eclipser::FuzzUntilEmpty(
    []( std::string &&m ) { std::cout << m << std::flush; },
    rng,
    options
  );
  BOOST_TEST_CHECKPOINT( "end fuzz" );
  std::uint32_t cov = 0u;
  std::size_t count = 0u;
  for( const auto &p: fs::directory_iterator( fs::path( options.out_dir ) / "queue" ) ) {
    const auto range = fuzzuf::utils::map_file( p.path().string(), O_RDONLY, false );
    if( range[ 0 ] == 'b' && range[ 1 ] == 'a' && range[ 2 ] == 0 && range[ 3 ] == 0 ) {
      cov |= ( 1u << 1 );
    }
    if( range[ 4 ] == 0 && range[ 5 ] == 0 && range[ 6 ] == 'A' && range[ 7 ] == 'B' ) {
      cov |= ( 1u << 0 );
    }
    const auto range_str = std::string( std::next( range.begin(), 8 ), range.end() );
    if( range_str.substr( 0, 5 ) == "Good!" ) {
      cov |= ( 1u << 2 );
    }
    if( range_str.substr( 0, 4 ) == "Bad!" ) {
      cov |= ( 1u << 3 );
    }
    ++count;
  }
  BOOST_CHECK_GE( count, 5u );
  BOOST_CHECK_EQUAL( cov, 0xFu );
}

