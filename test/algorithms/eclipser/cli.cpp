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
#define BOOST_TEST_MODULE algorithms.eclipser.cli
#define BOOST_TEST_DYN_LINK
#include <config.h>
#include <iostream>
#include <vector>
#include <fcntl.h>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <nlohmann/json.hpp>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/algorithms/eclipser/cli_compat/fuzzer.hpp"
#include "fuzzuf/cli/create_fuzzer_instance_from_argv.hpp"
#include "fuzzuf/cli/setup_execution_environment.hpp"

namespace {
std::vector< std::string > GetMandatoryArgs( const fs::path &output_dir ) {
  return std::vector< std::string >{
    "fuzzuf",
    "eclipser",
    "--outputdir",
    ( output_dir / "eclipser" ).string(),
    "--syncdir",
    output_dir.string(),
    "--program",
    TEST_BINARY_DIR "/put/raw/raw-linear",
    "--noforkserver"
  };
}
std::vector< const char* > GetRawArgs( const std::vector< std::string > &args ) {
  std::vector< const char* > raw_args;
  raw_args.reserve( args.size() );
  std::transform(
    args.begin(),
    args.end(),
    std::back_inserter( raw_args ),
    []( const auto &v ) {
      return v.c_str();
    }
  );
  return raw_args;
}
}

BOOST_AUTO_TEST_CASE(Run) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "-v" );
  args.push_back( "2" );
  args.push_back( "--filepath" );
  args.push_back( ( output_dir / "eclipser" / "seed" ).string() );
  args.push_back( "--arg" );
  args.push_back( ( output_dir / "eclipser" / "seed" ).string() );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  
  BOOST_TEST_CHECKPOINT( "begin fuzz" );
  eclipser->OneLoop();
  BOOST_TEST_CHECKPOINT( "end fuzz" );
  std::uint32_t cov = 0u;
  std::size_t count = 0u;
  for( const auto &p: fs::directory_iterator( fs::path( eclipser->GetOption().out_dir ) / "queue" ) ) {
    const auto range = fuzzuf::utils::map_file( p.path().string(), O_RDONLY, false );
    if( range[ 0 ] == 'A' ) {
      cov |= ( 1u << 0 );
    }
    if( range[ 0 ] == 'a' ) {
      cov |= ( 1u << 1 );
    }
    if( range[ 1 ] == 'B' && range[ 2 ] == 'A' ) {
      cov |= ( 1u << 2 );
    }
    if( range[ 1 ] == 'b' && range[ 2 ] == 'a' ) {
      cov |= ( 1u << 3 );
    }
    if( range[ 3 ] == 'D' && range[ 4 ] == 'C' && range[ 5 ] == 'B' && range[ 6 ] == 'A' ) {
      cov |= ( 1u << 4 );
    }
    if( range[ 3 ] == 'd' && range[ 4 ] == 'c' && range[ 5 ] == 'b' && range[ 6 ] == 'a' ) {
      cov |= ( 1u << 5 );
    }
    if( range[ 7 ] == 'H' && range[ 8 ] == 'G' && range[ 9 ] == 'F' && range[ 10 ] == 'E' && range[ 11 ] == 'D' && range[ 12 ] == 'C' && range[ 13 ] == 'B' && range[ 14 ] == 'A' ) {
      cov |= ( 1u << 6 );
    }
    if( range[ 7 ] == 'h' && range[ 8 ] == 'g' && range[ 9 ] == 'f' && range[ 10 ] == 'e' && range[ 11 ] == 'd' && range[ 12 ] == 'c' && range[ 13 ] == 'b' && range[ 14 ] == 'a' ) {
      cov |= ( 1u << 7 );
    }
    if( range[ 3 ] == 'q' && range[ 4 ] == 'r' && range[ 5 ] == 's' && range[ 6 ] == 't' ) {
      cov |= ( 1u << 8 );
    }
    ++count;
  }
  BOOST_CHECK_GE( count, 9u );
  BOOST_CHECK_EQUAL( cov, 0x1FFu );
}

