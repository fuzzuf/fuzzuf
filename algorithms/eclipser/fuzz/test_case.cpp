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
/**
 * @file test_case.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <string>
#include <fstream>
#include <boost/spirit/include/karma.hpp>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>
#include <fuzzuf/algorithms/eclipser/core/executor.hpp>
#include <fuzzuf/algorithms/eclipser/fuzz/test_case.hpp>

namespace fuzzuf::algorithm::eclipser::test_case {

namespace {
fs::path testcase_dir;
fs::path crash_dir;
}

void Initialize(
  const fs::path &out_dir
) {
  testcase_dir = out_dir / "queue";  
  fs::create_directories( testcase_dir );
  crash_dir = out_dir /"crashes";
  fs::create_directories( crash_dir );
}

namespace {
int total_segfaults = 0;
int total_illegals = 0;
int total_fpes = 0;
int total_aborts = 0;
int total_crashes = 0;
int total_test_cases = 0;
bool round_statistics_on = false;
int round_test_cases = 0;
}

void PrintStatistics(
  const std::function<void(std::string &&)> &sink
) {
  std::string message;
  message += "Testcases : ";
  message += std::to_string( total_test_cases );
  message += "\n";
  message += "Crashes : ";
  message += std::to_string( total_crashes );
  message += "\n";
  message += "  Segfault : ";
  message += std::to_string( total_segfaults );
  message += "\n";
  message += "  Illegal instruction : ";
  message += std::to_string( total_illegals );
  message += "\n";
  message += "  Floating point error : ";
  message += std::to_string( total_fpes );
  message += "\n";
  message += "  Program abortion : ";
  message += std::to_string( total_aborts );
  message += "\n";
  sink( std::move( message ) );
}

namespace {
void IncrCrashCount(
  Signal exit_sig
) {
  if( exit_sig == Signal::SIGSEGV ) {
    total_segfaults += 1;
  }
  else if( exit_sig == Signal::SIGILL ) {
    total_illegals += 1;
  }
  else if( exit_sig == Signal::SIGFPE ) {
    total_fpes += 1;
  }
  else if( exit_sig == Signal::SIGABRT ) {
    total_aborts += 1;
  }
  else
#if __GNUC__ >= 9 && __cplusplus > 201703L
  [[unlikely]]
#endif  
  {
    failwith( "updateCrashCount() called with a non-crashing exit signal" );
    return; // unreachable
  }
  total_crashes += 1;
}

}

void EnableRoundStatistics() {
  round_statistics_on = true;
}

void DisableRoundStatistics() {
  round_statistics_on = false;
}

int GetRoundTestCaseCount() {
  return round_test_cases;
}

void IncrTestCaseCount() {
  total_test_cases += 1;
  if( round_statistics_on ) {
    round_test_cases += 1;
  }
}

void ResetRoundTestCaseCount() {
  round_test_cases = 0;
}

namespace {

void DumpCrash(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  Signal exit_sig
) {
  if( opt.verbosity >= 1 ) {
    std::string message = "[*] Save crash seed : ";
    message += seed.ToString();
    sink( std::move( message ) );
  }
  std::array< char, 12u > crash_name = { 0 };
  crash_name[ 0 ] = 'i';
  crash_name[ 1 ] = 'd';
  crash_name[ 2 ] = ':';
  namespace karma = boost::spirit::karma;
  karma::generate(
    std::next( crash_name.data(), 3u ),
    karma::right_align( 6, '0' )[ karma::hex ],
    total_crashes
  );
  const auto crash_path = fs::path( crash_dir ) / crash_name.data();
  std::fstream fd( crash_path.c_str(), std::ios::out );
  const auto concretized = seed.Concretize();
  fd.write( reinterpret_cast< const char* >( concretized.data() ), concretized.size() );
  IncrCrashCount( exit_sig );
}

void DumpTestCase(
  const seed::Seed &seed
) {
  std::array< char, 12u > tc_name = { 0 };
  tc_name[ 0 ] = 'i';
  tc_name[ 1 ] = 'd';
  tc_name[ 2 ] = ':';
  namespace karma = boost::spirit::karma;
  karma::generate(
    std::next( tc_name.data(), 3u ),
    karma::right_align( 6, '0' )[ karma::hex ],
    total_test_cases
  );
  const auto tc_path = fs::path( testcase_dir ) / tc_name.data();
  std::fstream fd( tc_path.c_str(), std::ios::out );
  const auto concretized = seed.Concretize();
  fd.write( reinterpret_cast< const char* >( concretized.data() ), concretized.size() );
  IncrTestCaseCount();
}

std::pair< bool, Signal >
CheckCrash(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  Signal exit_sig,
  CoverageGain cov_gain
) {
  if( signal::IsCrash( exit_sig ) && cov_gain == CoverageGain::NewEdge ) {
    return std::make_pair( true, exit_sig );
  }
  else if( signal::IsTimeout( exit_sig ) ) {
    const auto new_exit_sig = executor::NativeExecute( sink, opt, seed );
    if( signal::IsCrash( new_exit_sig ) && cov_gain == CoverageGain::NewEdge ) {
      return std::make_pair( true, new_exit_sig );
    }
    else {
      return std::make_pair( false, new_exit_sig );
    }
  }
  else {
    return std::make_pair( false, exit_sig );
  }
}

}

void Save(
  const std::function<void(std::string &&)> &sink,
  const options::FuzzOption &opt,
  const seed::Seed &seed,
  Signal exit_sig,
  CoverageGain cov_gain
) {
  const auto [is_new_crash,new_exit_sig] = CheckCrash( sink, opt, seed, exit_sig, cov_gain );
  if( is_new_crash ) {
    DumpCrash( sink, opt, seed, new_exit_sig );
  }
  if( cov_gain == CoverageGain::NewEdge ) {
    DumpTestCase( seed );
  }
}

}

