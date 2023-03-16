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
#define BOOST_TEST_MODULE algorithms.eclipser.executor
#define BOOST_TEST_DYN_LINK
#include <config.h>

#include <array>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <nlohmann/json.hpp>
#include "fuzzuf/tests/standard_test_dirs.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"

BOOST_AUTO_TEST_CASE(Coverage) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-easy_to_branch",
  fuzzuf::algorithm::eclipser::executor::Initialize( options );
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain] = fuzzuf::algorithm::eclipser::executor::GetCoverage(
      []( std::string &&m ) { std::cout << m << std::flush; },
      options,
      seed
    );
#pragma GCC diagnostic pop
    BOOST_CHECK( signal == fuzzuf::algorithm::eclipser::Signal::NORMAL );
    BOOST_CHECK( coverage_gain == fuzzuf::algorithm::eclipser::CoverageGain::NewEdge );
  }
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain] = fuzzuf::algorithm::eclipser::executor::GetCoverage(
      []( std::string &&m ) { std::cout << m << std::flush; },
      options,
      seed
    );
#pragma GCC diagnostic pop
    BOOST_CHECK( signal == fuzzuf::algorithm::eclipser::Signal::NORMAL );
    BOOST_CHECK( coverage_gain == fuzzuf::algorithm::eclipser::CoverageGain::NoGain );
  }
}

BOOST_AUTO_TEST_CASE(BranchTrace) {
  FUZZUF_STANDARD_TEST_DIRS

  fuzzuf::algorithm::eclipser::options::FuzzOption options;
  options.verbosity = 1;
  options.out_dir = output_dir.string();
  options.target_prog = TEST_BINARY_DIR "/put/raw/raw-easy_to_branch",
  fuzzuf::algorithm::eclipser::executor::Initialize( options );
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ) } );
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
    BOOST_CHECK( signal == fuzzuf::algorithm::eclipser::Signal::NORMAL );
    BOOST_CHECK( coverage_gain == fuzzuf::algorithm::eclipser::CoverageGain::NewEdge );
    BOOST_CHECK( !branch_trace.empty() );
    trace = branch_trace;
  }
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ trace[ 0 ].inst_addr, 1u }
      );
#pragma GCC diagnostic pop
    BOOST_CHECK( signal == fuzzuf::algorithm::eclipser::Signal::NORMAL );
    BOOST_CHECK( coverage_gain == fuzzuf::algorithm::eclipser::CoverageGain::NewEdge );
    BOOST_CHECK( bool( branch_info_maybe ) );
    BOOST_CHECK( branch_info_maybe->operand1 == trace[ 0 ].operand1 );
    BOOST_CHECK( branch_info_maybe->operand2 == trace[ 0 ].operand2 );
    BOOST_CHECK( branch_info_maybe->distance == trace[ 0 ].distance );
    BOOST_CHECK( branch_info_maybe->operand_size == trace[ 0 ].operand_size );
    BOOST_CHECK( branch_info_maybe->try_value == trace[ 0 ].try_value );
  }
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Fixed{ std::byte( 0 ) } );
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto [signal,coverage_gain,branch_info_maybe] =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfo(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ trace[ 0 ].inst_addr, 1u }
      );
#pragma GCC diagnostic pop
    BOOST_CHECK( signal == fuzzuf::algorithm::eclipser::Signal::SIGABRT );
    BOOST_CHECK( coverage_gain == fuzzuf::algorithm::eclipser::CoverageGain::NewEdge );
    BOOST_CHECK( bool( branch_info_maybe ) );
    BOOST_CHECK( branch_info_maybe->inst_addr == trace[ 0 ].inst_addr );
    BOOST_CHECK( branch_info_maybe->operand1 == trace[ 0 ].operand1 );
    BOOST_CHECK( branch_info_maybe->operand2 == trace[ 0 ].operand2 );
    BOOST_CHECK( branch_info_maybe->distance == trace[ 0 ].distance );
    BOOST_CHECK( branch_info_maybe->operand_size == trace[ 0 ].operand_size );
    BOOST_CHECK( branch_info_maybe->try_value == trace[ 0 ].try_value );
  }
  {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
    const auto branch_info_maybe =
      fuzzuf::algorithm::eclipser::executor::GetBranchInfoOnly(
        []( std::string &&m ) { std::cout << m << std::flush; },
        options,
        seed,
        fuzzuf::algorithm::eclipser::BigInt( 0 ),
        fuzzuf::algorithm::eclipser::BranchPoint{ trace[ 0 ].inst_addr, 1u }
      );
#pragma GCC diagnostic pop
    BOOST_CHECK( bool( branch_info_maybe ) );
    BOOST_CHECK( branch_info_maybe->inst_addr == trace[ 0 ].inst_addr );
    BOOST_CHECK( branch_info_maybe->operand1 == trace[ 0 ].operand1 );
    BOOST_CHECK( branch_info_maybe->operand2 == trace[ 0 ].operand2 );
    BOOST_CHECK( branch_info_maybe->distance == trace[ 0 ].distance );
    BOOST_CHECK( branch_info_maybe->operand_size == trace[ 0 ].operand_size );
    BOOST_CHECK( branch_info_maybe->try_value == trace[ 0 ].try_value );
  }
}

