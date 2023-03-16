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
#define BOOST_TEST_MODULE algorithms.eclipser.monotonicity
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
#include "fuzzuf/algorithms/eclipser/gray_concolic/monotonicity.hpp"



BOOST_AUTO_TEST_CASE(Linear) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-threshold",
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
    const auto [signal,coverage_gain,branch_trace] =
      fuzzuf::algorithm::eclipser::executor::GetBranchTrace(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 )
      );
#pragma GCC diagnostic pop
    trace = branch_trace;
  }
  const auto branch = std::find_if(
    trace.begin(), trace.end(),
    []( const auto &v ) { return v.operand1 == 0x60 && v.operand2 == 0x4a; }
  );
  std::vector< fuzzuf::algorithm::eclipser::BranchInfo > triple;
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x10 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x10 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#pragma GCC diagnostic pop
      BOOST_CHECK( bool( branch_info_maybe ) );
      triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x20 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x20 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x30 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
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
  const auto result = fuzzuf::algorithm::eclipser::gray_concolic::monotonicity::Find(
    triple.begin(),
    triple.end()
  );
  BOOST_CHECK( bool( result ) );

  BOOST_CHECK_EQUAL( std::int64_t( result->lower_x ), 32 );
  BOOST_CHECK( bool( result->lower_y ) );
  BOOST_CHECK_EQUAL( std::int64_t( *result->lower_y ), 64 );
  BOOST_CHECK_EQUAL( std::int64_t( result->target_y ), 74 );
  BOOST_CHECK( result->tendency == fuzzuf::algorithm::eclipser::gray_concolic::Tendency::Incr );
  BOOST_CHECK_EQUAL( std::int64_t( result->upper_x ), 48 );
  BOOST_CHECK( bool( result->upper_y ) );
  BOOST_CHECK_EQUAL( std::int64_t( *result->upper_y ), 96 );
}

BOOST_AUTO_TEST_CASE(NonLinear) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-monotonic",
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
    const auto [signal,coverage_gain,branch_trace] =
      fuzzuf::algorithm::eclipser::executor::GetBranchTrace(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 )
      );
#pragma GCC diagnostic pop
    trace = branch_trace;
  }
  const auto branch = std::find_if(
    trace.begin(), trace.end(),
    []( const auto &v ) { return v.operand1 == 0x12 && v.operand2 == 0x4a; }
  );
  std::vector< fuzzuf::algorithm::eclipser::BranchInfo > triple;
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x30 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x30 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#pragma GCC diagnostic pop
      BOOST_CHECK( bool( branch_info_maybe ) );
      triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x70 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x70 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    triple.push_back( *branch_info_maybe );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Undecided{ std::byte( 0x90 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0x90 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ branch->inst_addr, 1u }
      );
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
  const auto result = fuzzuf::algorithm::eclipser::gray_concolic::monotonicity::Find(
    triple.begin(),
    triple.end()
  );
  BOOST_CHECK( bool( result ) );

  BOOST_CHECK_EQUAL( std::int64_t( result->lower_x ), 48 );
  BOOST_CHECK( bool( result->lower_y ) );
  BOOST_CHECK_EQUAL( std::int64_t( *result->lower_y ), 18 );
  BOOST_CHECK_EQUAL( std::int64_t( result->target_y ), 74 );
  BOOST_CHECK( result->tendency == fuzzuf::algorithm::eclipser::gray_concolic::Tendency::Incr );
  BOOST_CHECK_EQUAL( std::int64_t( result->upper_x ), 112 );
  BOOST_CHECK( bool( result->upper_y ) );
  BOOST_CHECK_EQUAL( std::int64_t( *result->upper_y ), 98 );
}

