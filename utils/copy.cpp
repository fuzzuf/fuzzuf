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
 * @file map_file.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#include <fstream>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "fuzzuf/utils/copy.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "config.h"

namespace fuzzuf::utils {

void copy( const fs::path &from, const fs::path &to ) {
#ifdef STATX_IS_DEFINED
  fs::copy( from, to );
#else
  const auto data = fuzzuf::utils::map_file( from.c_str(), O_RDONLY, true );
  std::fstream fd( to.c_str(), std::ios::out|std::ios::binary );
  fd.write( reinterpret_cast< char* >( &*data.begin() ), std::distance( data.begin(), data.end() ) );
#endif
}

}

