/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file executor.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#include <vector>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <boost/spirit/include/qi.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#include <elfio/elfio.hpp>
#pragma GCC diagnostic pop
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <unistd.h>
#include "fuzzuf/utils/instrumentation_info.hpp"

namespace fuzzuf::utils {

InstrumentationInfo get_instrumentation_info( const std::string &filename ) {
  ELFIO::elfio reader;
  if( !reader.load( filename.c_str() ) ) {
    return InstrumentationInfo();
  }
  const auto fuzzing_config = std::find_if(
    reader.sections.begin(),
    reader.sections.end(),
    []( const auto &v ) {
      return v->get_name() == ".fuzzing-config";
    }
  );
  if( fuzzing_config == reader.sections.end() ) {
    return InstrumentationInfo();
  }
  const auto fuzzing_config_data_begin = (*fuzzing_config)->get_data();
  const auto fuzzing_config_data_end = std::next(
    fuzzing_config_data_begin,
    (*fuzzing_config)->get_size()
  );
  const auto root = nlohmann::json::parse(
    fuzzing_config_data_begin,
    fuzzing_config_data_end
  );
  InstrumentationInfo info;
  if( !root.is_object() ) {
    return InstrumentationInfo();
  }

  if( root.find( "features" ) == root.end() ) {
    return InstrumentationInfo();
  }
  const auto &features = root[ "features" ];
  if( !features.is_object() ) {
    return InstrumentationInfo();
  }
  if( features.find( "forkServer" ) == features.end() ) {
    return InstrumentationInfo();
  }
  const auto &fork_server = features[ "forkServer" ];
  if( !fork_server.is_object() ) {
    return InstrumentationInfo();
  }
  if( fork_server.find( "verson" ) == fork_server.end() ) {
    return InstrumentationInfo();
  }
  const auto &version = fork_server[ "verson" ];
  if( !version.is_string() ) {
    return InstrumentationInfo();
  }
  const std::string version_str = version.get<std::string>();
  auto iter = version_str.begin();
  const auto end = version_str.end();
  unsigned int major = 0u;
  unsigned int minor = 0u;
  unsigned int patch = 0u;
  namespace qi = boost::spirit::qi;
  if( qi::parse(
    iter,
    end,
    qi::uint_ >> '.' >> qi::uint_ >> '.' >> qi::uint_,
    major,
    minor,
    patch
  ) && iter == end ) {
    info.major_version = major;
    info.minor_version = minor;
    info.patch_version = patch;
  }
  else {
    return InstrumentationInfo();
  }

  if( root.find( "params" ) == root.end() ) {
    return InstrumentationInfo();
  }
  const auto &params = root[ "params" ];
  if( !params.is_object() ) {
    return InstrumentationInfo();
  }
  
  if( params.find( "afl_coverage" ) != params.end() ) {
    if( params[ "afl_coverage" ].is_number() ) {
      if( params[ "afl_coverage" ] >= 1 ) {
        info.write_afl_coverage = true;
      }
    }
  }
  if( params.find( "ijon_max" ) != params.end() ) {
    if( params[ "ijon_max" ].is_number() ) {
      if( params[ "ijon_max" ] >= 1 ) {
        info.write_ijon_max = true;
      }
    }
  }
  if( params.find( "shm_input" ) != params.end() ) {
    if( params[ "shm_input" ].is_number() ) {
      if( params[ "shm_input" ] >= 1 ) {
        info.read_input_from_shared_memory = true;
      }
    }
  }
  info.instrumented = true;
  return info;
}

}

