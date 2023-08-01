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
#define BOOST_TEST_MODULE algorithms.eclipser.seed
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
#include "fuzzuf/algorithms/eclipser/gray_concolic/linear_equation.hpp"



BOOST_AUTO_TEST_CASE(Linear) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-threshold",
  options.fork_server = false;
  fuzzuf::algorithm::eclipser::options::SplitArgs( options );
  fuzzuf::algorithm::eclipser::executor::Initialize( options );
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ) } );
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );
  seed.SetCursorPosInplace( 0 );
  std::vector< fuzzuf::algorithm::eclipser::BranchInfo > trace;
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_trace] =
      fuzzuf::algorithm::eclipser::executor::GetBranchTrace(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 )
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
    trace = branch_trace;
  }
  const auto branch = std::find_if(
    trace.begin(), trace.end(),
    []( const auto &v ) { return v.operand1 == 0x60 && v.operand2 == 0x4a; }
  );
  std::vector< fuzzuf::algorithm::eclipser::BranchInfo > triple;
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x30 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
      BOOST_CHECK( bool( branch_info_maybe ) );
      triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x35 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x35 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x40 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x40 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    triple.push_back( *branch_info_maybe );
  }
  std::sort(
    triple.begin(), triple.end(),
    []( const auto &l, const auto &r ) {
      return l.try_value < r.try_value;
    }
  );
  fuzzuf::algorithm::eclipser::Context ctx;
  const auto byte_dir = seed.GetByteCursorDir();
  ctx.bytes = seed.QueryNeighborBytes( byte_dir );
  const auto result = fuzzuf::algorithm::eclipser::gray_concolic::linear_equation::Find(
    ctx,
    triple
  );
  BOOST_CHECK( bool( result ) );
  BOOST_CHECK_EQUAL( result->chunk_size, 1 );
  BOOST_CHECK_EQUAL( int( result->endian ), int( fuzzuf::algorithm::eclipser::Endian::BE ) );
  BOOST_CHECK_EQUAL( result->linearity.slope.numerator(), 2 );
  BOOST_CHECK_EQUAL( result->linearity.slope.denominator(), 1 );
  BOOST_CHECK_EQUAL( int( result->linearity.target ), 74 );
  BOOST_CHECK_EQUAL( int( result->linearity.x0 ), 48 );
  BOOST_CHECK_EQUAL( int( result->linearity.y0 ), 96 );
  BOOST_CHECK( !result->solutions.empty() );
  BOOST_CHECK_EQUAL( int( result->solutions[ 0 ] ), 37 );
}

BOOST_AUTO_TEST_CASE(NonLinear) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-monotonic",
  options.fork_server = false;
  fuzzuf::algorithm::eclipser::options::SplitArgs( options );
  fuzzuf::algorithm::eclipser::executor::Initialize( options );
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ) } );
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );
  seed.SetCursorPosInplace( 0 );
  std::vector< fuzzuf::algorithm::eclipser::BranchInfo > trace;
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_trace] =
      fuzzuf::algorithm::eclipser::executor::GetBranchTrace(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 )
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
    trace = branch_trace;
  }
  const auto branch = std::find_if(
    trace.begin(), trace.end(),
    []( const auto &v ) { return v.operand1 == 0x12 && v.operand2 == 0x4a; }
  );
  std::vector< fuzzuf::algorithm::eclipser::BranchInfo > triple;
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x10 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
      BOOST_CHECK( bool( branch_info_maybe ) );
      triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x35 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x15 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x40 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#if __GNUC__ < 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x20 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#if __GNUC__ < 8
#pragma GCC diagnostic pop
#endif
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    triple.push_back( *branch_info_maybe );
  }
  std::sort(
    triple.begin(), triple.end(),
    []( const auto &l, const auto &r ) {
      return l.try_value < r.try_value;
    }
  );
  fuzzuf::algorithm::eclipser::Context ctx;
  const auto byte_dir = seed.GetByteCursorDir();
  ctx.bytes = seed.QueryNeighborBytes( byte_dir );
  const auto result = fuzzuf::algorithm::eclipser::gray_concolic::linear_equation::Find(
    ctx,
    triple
  );
  BOOST_CHECK( !bool( result ) );
}
