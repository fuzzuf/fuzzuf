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
#define BOOST_TEST_MODULE algorithms.eclipser.cli_parser
#define BOOST_TEST_DYN_LINK
#include <config.h>
#include <iostream>
#include <vector>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <nlohmann/json.hpp>
#include "fuzzuf/utils/filesystem.hpp"
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

BOOST_AUTO_TEST_CASE(DefaultVerbosity) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().verbosity, 0 );
}

BOOST_AUTO_TEST_CASE(Verbosity) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "-v" );
  args.push_back( "2" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().verbosity, 2 );
}

BOOST_AUTO_TEST_CASE(DefaultTimeLimit) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().timelimit, -1 );
}

BOOST_AUTO_TEST_CASE(TimeLimit) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--timelimit" );
  args.push_back( "5" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().timelimit, 5 );
}

BOOST_AUTO_TEST_CASE(DefaultExecTimeout) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().exec_timeout, 500 );
}

BOOST_AUTO_TEST_CASE(ExecTimeout) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--exectimeout" );
  args.push_back( "700" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().exec_timeout, 700 );
}

BOOST_AUTO_TEST_CASE(DefaultArchitecture) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( nlohmann::json( eclipser->GetOption().architecture ).dump(), nlohmann::json( fuzzuf::algorithm::eclipser::Arch::X64 ).dump() );
}

BOOST_AUTO_TEST_CASE(Architecture) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--architecture" );
  args.push_back( "x86" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( nlohmann::json( eclipser->GetOption().architecture ).dump(), nlohmann::json( fuzzuf::algorithm::eclipser::Arch::X86 ).dump() );
}

BOOST_AUTO_TEST_CASE(DefaultInputDir) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().input_dir, "" );
}

BOOST_AUTO_TEST_CASE(InputDir) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--inputdir" );
  args.push_back( input_dir.string() );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().input_dir, input_dir.string() );
}

BOOST_AUTO_TEST_CASE(DefaultArg) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().arg, "" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args.size(), 1 );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args[ 0 ], TEST_BINARY_DIR "/put/raw/raw-linear" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_raw_args.size(), 1 );
  BOOST_CHECK_EQUAL( std::string( eclipser->GetOption().native_raw_args[ 0 ] ), TEST_BINARY_DIR "/put/raw/raw-linear" );
  constexpr static std::array< fuzzuf::algorithm::eclipser::Tracer, 3u > tracers{
    fuzzuf::algorithm::eclipser::Tracer::Coverage,
    fuzzuf::algorithm::eclipser::Tracer::Branch,
    fuzzuf::algorithm::eclipser::Tracer::BBCount
  };
  const auto exec_dir = fs::canonical( "/proc/self/exe" ).parent_path();
  std::unordered_map< fuzzuf::algorithm::eclipser::Tracer, fs::path > tracer_bin_name {
    { fuzzuf::algorithm::eclipser::Tracer::Coverage, exec_dir / "qemu-trace-coverage-x64" },
    { fuzzuf::algorithm::eclipser::Tracer::Branch, exec_dir / "qemu-trace-branch-x64" },
    { fuzzuf::algorithm::eclipser::Tracer::BBCount, exec_dir / "qemu-trace-bbcount-x64" }
  };
  for( auto t: tracers ) {
    {
      const auto iter = eclipser->GetOption().splited_args.find( t );
      BOOST_CHECK( iter != eclipser->GetOption().splited_args.end() );
      BOOST_CHECK_EQUAL( iter->second.size(), 1 );
      BOOST_CHECK_EQUAL( fs::path( iter->second[ 0 ] ), tracer_bin_name[ t ] );
    }
    {
      const auto iter = eclipser->GetOption().raw_args.find( t );
      BOOST_CHECK( iter != eclipser->GetOption().raw_args.end() );
      BOOST_CHECK_EQUAL( iter->second.size(), 2 );
      BOOST_CHECK_EQUAL( fs::path( iter->second[ 0 ] ), tracer_bin_name[ t ] );
      BOOST_CHECK_EQUAL( std::string( iter->second[ 1 ] ), TEST_BINARY_DIR "/put/raw/raw-linear" );
    }
  }
}

BOOST_AUTO_TEST_CASE(Arg) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--arg" );
  args.push_back( "hoge fuga piyo" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().arg, "hoge fuga piyo" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args.size(), 4 );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args[ 0 ], TEST_BINARY_DIR "/put/raw/raw-linear" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args[ 1 ], "hoge" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args[ 2 ], "fuga" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_splited_args[ 3 ], "piyo" );
  BOOST_CHECK_EQUAL( eclipser->GetOption().native_raw_args.size(), 4 );
  BOOST_CHECK_EQUAL( std::string( eclipser->GetOption().native_raw_args[ 0 ] ), TEST_BINARY_DIR "/put/raw/raw-linear" );
  BOOST_CHECK_EQUAL( std::string( eclipser->GetOption().native_raw_args[ 1 ] ), "hoge" );
  BOOST_CHECK_EQUAL( std::string( eclipser->GetOption().native_raw_args[ 2 ] ), "fuga" );
  BOOST_CHECK_EQUAL( std::string( eclipser->GetOption().native_raw_args[ 3 ] ), "piyo" );
  constexpr static std::array< fuzzuf::algorithm::eclipser::Tracer, 3u > tracers{
    fuzzuf::algorithm::eclipser::Tracer::Coverage,
    fuzzuf::algorithm::eclipser::Tracer::Branch,
    fuzzuf::algorithm::eclipser::Tracer::BBCount
  };
  const auto exec_dir = fs::canonical( "/proc/self/exe" ).parent_path();
  std::unordered_map< fuzzuf::algorithm::eclipser::Tracer, fs::path > tracer_bin_name {
    { fuzzuf::algorithm::eclipser::Tracer::Coverage, exec_dir / "qemu-trace-coverage-x64" },
    { fuzzuf::algorithm::eclipser::Tracer::Branch, exec_dir / "qemu-trace-branch-x64" },
    { fuzzuf::algorithm::eclipser::Tracer::BBCount, exec_dir / "qemu-trace-bbcount-x64" }
  };
  for( auto t: tracers ) {
    {
      const auto iter = eclipser->GetOption().splited_args.find( t );
      BOOST_CHECK( iter != eclipser->GetOption().splited_args.end() );
      BOOST_CHECK_EQUAL( iter->second.size(), 1 );
      BOOST_CHECK_EQUAL( fs::path( iter->second[ 0 ] ), tracer_bin_name[ t ] );
    }
    {
      const auto iter = eclipser->GetOption().raw_args.find( t );
      BOOST_CHECK( iter != eclipser->GetOption().raw_args.end() );
      BOOST_CHECK_EQUAL( iter->second.size(), 5 );
      BOOST_CHECK_EQUAL( fs::path( iter->second[ 0 ] ), tracer_bin_name[ t ] );
      BOOST_CHECK_EQUAL( std::string( iter->second[ 1 ] ), TEST_BINARY_DIR "/put/raw/raw-linear" );
      BOOST_CHECK_EQUAL( std::string( iter->second[ 2 ] ), "hoge" );
      BOOST_CHECK_EQUAL( std::string( iter->second[ 3 ] ), "fuga" );
      BOOST_CHECK_EQUAL( std::string( iter->second[ 4 ] ), "piyo" );
    }
  }
}

BOOST_AUTO_TEST_CASE(DefaultFuzzSource) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().fuzz_source.index(), 0 );
}

BOOST_AUTO_TEST_CASE(FuzzSource) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--filepath" );
  args.push_back( ( output_dir / "eclipser" / "seed" ).string() );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().fuzz_source.index(), 1 );
  BOOST_CHECK_EQUAL( std::get< fuzzuf::algorithm::eclipser::FileInput >( eclipser->GetOption().fuzz_source ).filepath, ( output_dir / "eclipser" / "seed" ).string() );
}

BOOST_AUTO_TEST_CASE(DefaultNSolve) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().n_solve, 600 );
}

BOOST_AUTO_TEST_CASE(NSolve) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--nsolve" );
  args.push_back( "123" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().n_solve, 123 );
}

BOOST_AUTO_TEST_CASE(DefaultNSpawn) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().n_spawn, 10 );
}

BOOST_AUTO_TEST_CASE(NSpawn) {
  FUZZUF_STANDARD_TEST_DIRS
  fuzzuf::cli::SetupExecutionEnvironment();
  std::vector< std::string > args = GetMandatoryArgs( output_dir );
  args.push_back( "--nspawn" );
  args.push_back( "13" );
  auto raw_args = GetRawArgs( args );
  auto fuzzer = fuzzuf::cli::CreateFuzzerInstanceFromArgv( raw_args.size(), raw_args.data() );
  const std::unique_ptr< fuzzuf::algorithm::eclipser::EclipserFuzzer > eclipser(
    dynamic_cast< fuzzuf::algorithm::eclipser::EclipserFuzzer* >( fuzzer.get() )
  );
  fuzzer.release();
  BOOST_CHECK_EQUAL( eclipser->GetOption().n_spawn, 13 );
}

