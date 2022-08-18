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
#include <bfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "fuzzuf/utils/instrumentation_info.hpp"

namespace fuzzuf::utils {

InstrumentationInfo get_instrumentation_info( const std::string &filename ) {
  auto fd = bfd_openr( filename.c_str(), nullptr );
  if( !fd )
    return InstrumentationInfo();
  bfd_check_format( fd, bfd_object);
  const auto section = bfd_get_section_by_name( fd, ".fuzzuf" );
  std::vector< std::uint8_t > section_data(
#ifdef bfd_get_section_size
    reinterpret_cast< std::uintptr_t >( bfd_get_section_size( section ) )
#else
    bfd_section_size( section )
#endif
  );
  if( !bfd_get_section_contents( fd, section, section_data.data(), 0, section_data.size() ) )
    return InstrumentationInfo();
  const auto symtab_size = bfd_get_symtab_upper_bound( fd );
  if( symtab_size <= 0 )
    return InstrumentationInfo();
  std::vector< asymbol* > symbols( symtab_size / sizeof( asymbol* ) );
  const auto symbol_count = bfd_canonicalize_symtab( fd, symbols.data() );
  InstrumentationInfo info;
  info.instrumented = true;
  if( symbol_count < 0 )
    return InstrumentationInfo();
  for (int i = 0; i < symbol_count; i++) {
    if( symbols[ i ] &&  symbols[ i ]->section && symbols[ i ]->section->name && std::strncmp( symbols[ i ]->section->name, ".fuzzuf", 7u ) == 0 ) {
      const auto name = std::string( bfd_asymbol_name( symbols[ i ] ) );
      const auto offset = symbols[ i ]->value;
      if( offset < section_data.size() ) {
        const auto value = section_data[ offset ];
        if( name == "__fuzzuf_cc_major_version" ) {
          info.major_version = value;
        }
	else if( name == "__fuzzuf_cc_minor_version" ) {
	  info.minor_version = value;
	}
	else if( name == "__fuzzuf_cc_patch_version" ) {
	  info.patch_version = value;
	}
	else if( name == "__fuzzuf_cc_afl_coverage" ) {
	  info.write_afl_coverage = value;
	}
	else if( name == "__fuzzuf_cc_ijon_max" ) {
	  info.write_ijon_max = value;
	}
	else if( name == "__fuzzuf_cc_shm_input" ) {
	  info.read_input_from_shared_memory = value;
	}
      }
    }
  }
  bfd_close( fd );
  return info;
}

}

