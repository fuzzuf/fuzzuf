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
#define BOOST_TEST_MODULE algorithms.eclipser.branch_tree
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
#include "fuzzuf/algorithms/eclipser/core/branch_info.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/branch_trace.hpp"
#include "fuzzuf/algorithms/eclipser/gray_concolic/branch_tree.hpp"



BOOST_AUTO_TEST_CASE(Linear) {
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
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
  const auto [branch_traces,candidates] = fuzzuf::algorithm::eclipser::gray_concolic::branch_trace::Collect(
    []( std::string &&m ) { std::cout << m << std::flush; },
    seed,
    options,
    fuzzuf::algorithm::eclipser::BigInt( 0 ),
    fuzzuf::algorithm::eclipser::BigInt( 127 )
  );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
  const auto byte_dir = seed.GetByteCursorDir();
  const auto bytes = seed.QueryNeighborBytes( byte_dir );
  fuzzuf::algorithm::eclipser::Context ctx{ bytes, byte_dir };
  const auto result = fuzzuf::algorithm::eclipser::gray_concolic::branch_tree::Make(
    options,
    ctx,
    branch_traces
  );

  BOOST_CHECK_EQUAL( result.which(), 1 );

  const auto &forked = boost::get< fuzzuf::algorithm::eclipser::gray_concolic::ForkedTree >( result );
  const auto &branch_condition = std::get< 1 >( forked );
  const auto &ineq = std::get< fuzzuf::algorithm::eclipser::gray_concolic::LinearInequality >( branch_condition.first );

  BOOST_CHECK( ineq.sign == fuzzuf::algorithm::eclipser::Signedness::Signed );
  BOOST_CHECK( bool( ineq.tight_inequality ) );
  BOOST_CHECK_EQUAL( ineq.tight_inequality->chunk_size, 1 );
  BOOST_CHECK( ineq.tight_inequality->endian == fuzzuf::algorithm::eclipser::Endian::BE );
  BOOST_CHECK_EQUAL( std::int64_t( ineq.tight_inequality->linearity.slope.denominator() ), 1 );
  BOOST_CHECK_EQUAL( std::int64_t( ineq.tight_inequality->linearity.slope.numerator() ), 2 );
  BOOST_CHECK_EQUAL( std::int64_t( ineq.tight_inequality->linearity.target ), 74 );
  BOOST_CHECK_EQUAL( std::int64_t( ineq.tight_inequality->linearity.x0 ), 0 );
  BOOST_CHECK_EQUAL( std::int64_t( ineq.tight_inequality->linearity.y0 ), 0 );
  BOOST_CHECK_EQUAL( ineq.tight_inequality->solutions.size(), 1 );
  BOOST_CHECK_EQUAL( std::int64_t( ineq.tight_inequality->solutions[ 0 ] ), 37 );
}

