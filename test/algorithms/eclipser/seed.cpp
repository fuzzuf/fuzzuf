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


BOOST_AUTO_TEST_CASE(EmptySeed) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  {
    const auto result = seed.Concretize();
    std::vector< std::byte > expected{};
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}
BOOST_AUTO_TEST_CASE(FixCurBytesRight) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ) } );
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 2 ) } );
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 3 ) } );
  {
    const auto result = seed.Concretize();
    std::vector< std::byte > expected{ std::byte( 3 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}
BOOST_AUTO_TEST_CASE(FixCurBytesRightMultiple) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ) } );
  {
    const auto result = seed.Concretize();
    std::vector< std::byte > expected{ std::byte( 1 ), std::byte( 2 ), std::byte( 3 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}

BOOST_AUTO_TEST_CASE(StepCursor) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ) } );
  seed.StepCursorInplace();
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 4 ) } );
  {
    const auto result = seed.Concretize();
    std::vector< std::byte > expected{ std::byte( 1 ), std::byte( 4 ), std::byte( 3 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}

BOOST_AUTO_TEST_CASE(GetCurLength) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  seed.StepCursorInplace();
  BOOST_CHECK_EQUAL( seed.GetCurLength(), 5u );
}

BOOST_AUTO_TEST_CASE(FixCurBytesLeft) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Left, { std::byte( 6 ), std::byte( 7 ) } );
  {
    const auto result = seed.Concretize();
    std::vector< std::byte > expected{ std::byte( 1 ), std::byte( 2 ), std::byte( 6 ), std::byte( 7 ), std::byte( 5 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}

BOOST_AUTO_TEST_CASE(GetByteCursorDir) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Right );
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Left );
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Left );
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Stay );
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Stay );
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Right );
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Right );
  seed.SetByteCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Left );
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Left );
  seed.SetByteCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Stay );
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Stay );
  seed.SetByteCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Right );
  BOOST_CHECK_EQUAL( seed.GetByteCursorDir(), fuzzuf::algorithm::eclipser::Direction::Right );
}


BOOST_AUTO_TEST_CASE(GetConcreteByteAt) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  seed.StepCursorInplace();
  {
    const auto result = seed.GetConcreteByteAt( 4 );
    BOOST_CHECK_EQUAL( result, std::byte( 5 ) );
  }
  {
    const auto result = seed.GetConcreteByteAt();
    BOOST_CHECK_EQUAL( result, std::byte( 2 ) );
  }
}

BOOST_AUTO_TEST_CASE(GetConcreteBytesFrom) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  {
    const auto result = seed.GetConcreteBytesFrom( 1, 2 );
    std::vector< std::byte > expected{ std::byte( 2 ), std::byte( 3 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}

BOOST_AUTO_TEST_CASE(HasUnfixedByte) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  BOOST_CHECK_EQUAL( seed.HasUnfixedByte(), false );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  BOOST_CHECK_EQUAL( seed.HasUnfixedByte(), true );
  BOOST_CHECK_EQUAL( seed.IsUnfixedByteAt( 0 ), false );
  BOOST_CHECK_EQUAL( seed.IsUnfixedByteAt( 1 ), true );
  BOOST_CHECK_EQUAL( seed.IsUnfixedByteAt(), true );
}

BOOST_AUTO_TEST_CASE(QueryLenToward) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  seed.StepCursorInplace();
  BOOST_CHECK_EQUAL( seed.QueryLenToward( fuzzuf::algorithm::eclipser::Direction::Left ), 2u );
  BOOST_CHECK_EQUAL( seed.QueryLenToward( fuzzuf::algorithm::eclipser::Direction::Right ), 4u );
}

BOOST_AUTO_TEST_CASE(GetUnfixedByteIndex) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  BOOST_CHECK_EQUAL( seed.GetUnfixedByteIndex(), 1u );
}

BOOST_AUTO_TEST_CASE(QueryUpdateBound) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ), std::byte( 7 ), std::byte( 8 ), std::byte( 9 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  seed.StepCursorInplace();
  seed.UpdateCurByteInplace( fuzzuf::algorithm::eclipser::byteval::Interval{ std::byte( 10 ), std::byte( 20 ) } );
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Left );
  seed.StepCursorInplace();
  BOOST_CHECK_EQUAL( seed.QueryUpdateBound( fuzzuf::algorithm::eclipser::Direction::Right ), 2u );
  BOOST_CHECK_EQUAL( seed.QueryUpdateBound( fuzzuf::algorithm::eclipser::Direction::Left ), 4u );
  BOOST_CHECK_EQUAL( seed.QueryUpdateBound(), 4u );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  BOOST_CHECK_EQUAL( seed.QueryUpdateBound( fuzzuf::algorithm::eclipser::Direction::Right ), 0u );
  BOOST_CHECK_EQUAL( seed.QueryUpdateBound( fuzzuf::algorithm::eclipser::Direction::Left ), 0u );
  BOOST_CHECK_EQUAL( seed.QueryUpdateBound(), 0u );
}

BOOST_AUTO_TEST_CASE(QueryNeighborBytes) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  {
    const auto result = seed.QueryNeighborBytes( fuzzuf::algorithm::eclipser::Direction::Right );
    std::vector< std::byte > expected{ std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
  {
    const auto result = seed.QueryNeighborBytes( fuzzuf::algorithm::eclipser::Direction::Left );
    std::vector< std::byte > expected{ std::byte( 1 ), std::byte( 2 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
  {
    const auto result = seed.QueryNeighborBytes();
    std::vector< std::byte > expected{ std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Left );
  {
    const auto result = seed.QueryNeighborBytes();
    std::vector< std::byte > expected{ std::byte( 1 ), std::byte( 2 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}

BOOST_AUTO_TEST_CASE(ConstrainByteRight) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.ConstrainByteAtInplace( fuzzuf::algorithm::eclipser::Direction::Right, 1, std::byte( 21 ), std::byte( 53 ) );
  {
    const auto result = seed.Concretize();
    BOOST_CHECK_EQUAL( result.size(), 6u );
    BOOST_CHECK_EQUAL( result[ 0 ], std::byte( 1 ) );
    BOOST_CHECK_EQUAL( result[ 1 ], std::byte( 2 ) );
    BOOST_CHECK_EQUAL( result[ 2 ], std::byte( 3 ) );
    BOOST_CHECK_EQUAL( result[ 3 ], std::byte( 4 ) );
    BOOST_CHECK_GE( result[ 4 ], std::byte( 21 ) );
    BOOST_CHECK_LE( result[ 4 ], std::byte( 53 ) );
    BOOST_CHECK_EQUAL( result[ 5 ], std::byte( 6 ) );
  }
}

BOOST_AUTO_TEST_CASE(ConstrainByteLeft) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.ConstrainByteAtInplace( fuzzuf::algorithm::eclipser::Direction::Left, 1, std::byte( 21 ), std::byte( 53 ) );
  {
    const auto result = seed.Concretize();
    BOOST_CHECK_EQUAL( result.size(), 6u );
    BOOST_CHECK_EQUAL( result[ 0 ], std::byte( 1 ) );
    BOOST_CHECK_EQUAL( result[ 1 ], std::byte( 2 ) );
    BOOST_CHECK_GE( result[ 2 ], std::byte( 21 ) );
    BOOST_CHECK_LE( result[ 2 ], std::byte( 53 ) );
    BOOST_CHECK_EQUAL( result[ 3 ], std::byte( 4 ) );
    BOOST_CHECK_EQUAL( result[ 4 ], std::byte( 5 ) );
    BOOST_CHECK_EQUAL( result[ 5 ], std::byte( 6 ) );
  }
}

BOOST_AUTO_TEST_CASE(ConstrainByteRightByCursorDirection) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.ConstrainByteAtInplace( 1, std::byte( 21 ), std::byte( 53 ) );
  {
    const auto result = seed.Concretize();
    BOOST_CHECK_EQUAL( result.size(), 6u );
    BOOST_CHECK_EQUAL( result[ 0 ], std::byte( 1 ) );
    BOOST_CHECK_EQUAL( result[ 1 ], std::byte( 2 ) );
    BOOST_CHECK_EQUAL( result[ 2 ], std::byte( 3 ) );
    BOOST_CHECK_EQUAL( result[ 3 ], std::byte( 4 ) );
    BOOST_CHECK_GE( result[ 4 ], std::byte( 21 ) );
    BOOST_CHECK_LE( result[ 4 ], std::byte( 53 ) );
    BOOST_CHECK_EQUAL( result[ 5 ], std::byte( 6 ) );
  }
}

BOOST_AUTO_TEST_CASE(ConstrainByteLeftByCursorDirection) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Left );
  seed.ConstrainByteAtInplace( 1, std::byte( 21 ), std::byte( 53 ) );
  {
    const auto result = seed.Concretize();
    BOOST_CHECK_EQUAL( result.size(), 6u );
    BOOST_CHECK_EQUAL( result[ 0 ], std::byte( 1 ) );
    BOOST_CHECK_EQUAL( result[ 1 ], std::byte( 2 ) );
    BOOST_CHECK_GE( result[ 2 ], std::byte( 21 ) );
    BOOST_CHECK_LE( result[ 2 ], std::byte( 53 ) );
    BOOST_CHECK_EQUAL( result[ 3 ], std::byte( 4 ) );
    BOOST_CHECK_EQUAL( result[ 4 ], std::byte( 5 ) );
    BOOST_CHECK_EQUAL( result[ 5 ], std::byte( 6 ) );
  }
}

BOOST_AUTO_TEST_CASE(FixCurBytes) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.ConstrainByteAtInplace( 0, std::byte( 21 ), std::byte( 53 ) );
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 8 ), std::byte( 9 ) } );
  { 
    const auto result = seed.Concretize();
    BOOST_CHECK_EQUAL( result.size(), 6u );
    BOOST_CHECK_EQUAL( result[ 0 ], std::byte( 1 ) );
    BOOST_CHECK_EQUAL( result[ 1 ], std::byte( 2 ) );
    BOOST_CHECK_EQUAL( result[ 2 ], std::byte( 3 ) );
    BOOST_CHECK_EQUAL( result[ 3 ], std::byte( 8 ) );
    BOOST_CHECK_EQUAL( result[ 4 ], std::byte( 9 ) );
    BOOST_CHECK_EQUAL( result[ 5 ], std::byte( 6 ) );
  }
}

BOOST_AUTO_TEST_CASE(FixCurBytesByCursorDir) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.StepCursorInplace();
  seed.ConstrainByteAtInplace( 0, std::byte( 21 ), std::byte( 53 ) );
  seed.SetCursorDirInplace( fuzzuf::algorithm::eclipser::Direction::Left );
  seed.FixCurBytesInplace( { std::byte( 8 ), std::byte( 9 ) } );
  { 
    const auto result = seed.Concretize();
    BOOST_CHECK_EQUAL( result.size(), 6u );
    BOOST_CHECK_EQUAL( result[ 0 ], std::byte( 1 ) );
    BOOST_CHECK_EQUAL( result[ 1 ], std::byte( 2 ) );
    BOOST_CHECK_EQUAL( result[ 2 ], std::byte( 8 ) );
    BOOST_CHECK_EQUAL( result[ 3 ], std::byte( 9 ) );
    BOOST_CHECK_EQUAL( result[ 4 ], std::byte( 5 ) );
    BOOST_CHECK_EQUAL( result[ 5 ], std::byte( 6 ) );
  }
}

BOOST_AUTO_TEST_CASE(SetCursorPos) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.SetCursorPosInplace( 3 );
  seed.FixCurBytesInplace( { std::byte( 8 ), std::byte( 9 ) } );
  seed.SetCursorPosInplace( 1 );
  seed.FixCurBytesInplace( { std::byte( 10 ) } );
  {
    const auto result = seed.Concretize();
    std::vector< std::byte > expected{ std::byte( 1 ), std::byte( 10 ), std::byte( 3 ), std::byte( 8 ), std::byte( 9 ), std::byte( 6 ) };
    BOOST_CHECK_EQUAL( expected.size(), result.size() );
    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(),
                                result.begin(), result.end());
  }
}

BOOST_AUTO_TEST_CASE(ProceedCursor) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  seed.SetCursorPosInplace( 3 );
  seed.ConstrainByteAtInplace( 0, std::byte( 21 ), std::byte( 53 ) );
  seed.SetCursorPosInplace( 0 );
  seed.ProceedCursorInplace();
  const auto value = seed.GetConcreteByteAt();
  BOOST_CHECK_GE( value, std::byte( 21 ) );
  BOOST_CHECK_LE( value, std::byte( 53 ) );
}

BOOST_AUTO_TEST_CASE(ShuffleByteCursor) {
  fuzzuf::algorithm::eclipser::seed::Seed seed;
  seed.FixCurBytesInplace( fuzzuf::algorithm::eclipser::Direction::Right, { std::byte( 1 ), std::byte( 2 ), std::byte( 3 ), std::byte( 4 ), std::byte( 5 ), std::byte( 6 ) } );
  std::mt19937 rng{ std::random_device{}() };
  seed.ShuffleByteCursorInplace( rng );
  const auto value = seed.GetConcreteByteAt();
  BOOST_CHECK_GE( value, std::byte( 1 ) );
  BOOST_CHECK_LE( value, std::byte( 6 ) );
}

