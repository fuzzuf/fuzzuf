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

#include <fstream>
#include <boost/spirit/include/karma.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/kscheduler/dump_coverage.hpp>
#include <fuzzuf/utils/common.hpp>

namespace fuzzuf::utils::kscheduler {
  void DumpCoverage(
    const fs::path &filename,
    const std::vector< std::uint8_t > &virgin_bits
  ) {
    std::fstream fd( filename.string(), std::ios::out );
    if( !fd.good() ) {
      throw exceptions::invalid_argument( std::string( "fuzzuf::utils::DumpCoverage : " ) + filename.string() + " : Cannot create file", __FILE__, __LINE__ );
    }
    std::vector< char > buffer;
    namespace karma = boost::spirit::karma;
    for( std::size_t i = 0u; i != virgin_bits.size(); ++i ) {
      if( unlikely( virgin_bits[ i ] != 0xff ) ) {
        karma::generate( std::back_inserter( buffer ), karma::uint_ << ' ', i + 1u );
      }
    }
    fd.write( buffer.data(), buffer.size() );
  }
}
