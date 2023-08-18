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
 * @file options.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <algorithm>
#include <nlohmann/json.hpp>
#include "fuzzuf/algorithms/eclipser/core/options.hpp"
#include "fuzzuf/algorithms/eclipser/core/executor.hpp"

namespace fuzzuf::algorithm::eclipser::options {

void to_json( nlohmann::json &dest, const FuzzOption &src ) {
  dest = nlohmann::json::object();
  dest[ "verbosity" ] = src.verbosity;
  dest[ "timelimit" ] = src.timelimit;
  dest[ "out_dir" ] = src.out_dir;
  dest[ "sync_dir" ] = src.sync_dir;
  dest[ "target_prog" ] = src.target_prog;
  dest[ "exec_timeout" ] = src.exec_timeout;
  dest[ "architecture" ] = src.architecture;
  dest[ "fork_server" ] = src.fork_server;
  dest[ "input_dir" ] = src.input_dir;
  dest[ "arg" ] = src.arg;
  dest[ "fuzz_source" ] = src.fuzz_source;
  dest[ "n_solve" ] = src.n_solve;
  dest[ "n_spawn" ] = src.n_spawn;
  dest[ "args" ] = nlohmann::json::object();
  constexpr static std::array< Tracer, 3u > tracers{
    Tracer::Coverage,
    Tracer::Branch,
    Tracer::BBCount
  };
  for( Tracer t: tracers ) {
    auto iter = src.raw_args.find( t );
    if( iter != src.raw_args.end() ) {
      const auto tn = to_string( t );
      dest[ "args" ][ tn ] = nlohmann::json::array();
      for( const auto &s: iter->second ) {
        dest[ "args" ][ tn ].push_back( s );
      }
    }
  }
  {
    dest[ "args" ][ "Native" ] = nlohmann::json::array();
    for( const auto &s: src.native_raw_args ) {
      dest[ "args" ][ "Native" ].push_back( s );
    }
  }
}

void SplitArgs( FuzzOption &opts ) {
  const auto arg = executor::SplitCmdLineArg( opts.arg );
  constexpr static std::array< Tracer, 3u > tracers{
    Tracer::Coverage,
    Tracer::Branch,
    Tracer::BBCount
  };
  {
    std::vector< std::string > cmd{ opts.target_prog };
    cmd.reserve( arg.size() + 1u );
    cmd.insert(
      cmd.end(),
      arg.begin(),
      arg.end()
    );
    opts.native_splited_args = std::move( cmd );
    std::vector< char* > raw;
    raw.reserve( arg.size() + 1u );
    std::transform(
      opts.native_splited_args.begin(),
      opts.native_splited_args.end(),
      std::back_inserter( raw ),
      []( const auto &v ) {
        return const_cast< char* >( v.c_str() );
      }
    );
    opts.native_raw_args = std::move( raw );
  }
  for( Tracer t: tracers ) {
    opts.splited_args.insert(
      std::make_pair(
        t,
	std::vector< std::string >{
	  executor::SelectTracer( t, opts.architecture ).string()
	}
      )
    );
    std::vector< char* > raw;
    raw.reserve( arg.size() + 2u );
    auto iter = opts.splited_args.find( t );
    std::transform(
      iter->second.begin(),
      iter->second.end(),
      std::back_inserter( raw ),
      []( const auto &v ) {
        return const_cast< char* >( v.c_str() );
      }
    );
    std::transform(
      opts.native_splited_args.begin(),
      opts.native_splited_args.end(),
      std::back_inserter( raw ),
      []( const auto &v ) {
        return const_cast< char* >( v.c_str() );
      }
    );
    opts.raw_args.insert(
      std::make_pair(
        t,
        std::move( raw )
      )
    );
  }
}

}
