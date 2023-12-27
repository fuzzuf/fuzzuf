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

#include <fcntl.h>
#include <vector>
#include <utility>
#include <cstdint>
#include <boost/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/fusion/container/vector.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/map_file.hpp>
#include <fuzzuf/utils/kscheduler/load_child_node.hpp>

namespace fuzzuf::utils::kscheduler {

std::vector< std::pair< std::uint32_t, std::uint32_t > >
LoadChildNode(
  const fs::path &filename
) {
  const auto range = map_file( filename.string(), O_RDONLY, true );
  auto iter = range.begin();
  const auto end = range.end();
  std::vector< std::vector< std::uint32_t > > temp;
  namespace qi = boost::spirit::qi;
  if (!qi::parse(iter, end,
                 ( qi::uint_ % qi::standard::blank ) % qi::eol >> qi::omit[ *qi::standard::space ],
                 temp) ||
      iter != end) {
    throw exceptions::invalid_argument( std::string( "fuzzuf::utils::LoadChildNode : " ) + filename.string() + " : The file is broken", __FILE__, __LINE__ );
  }
  std::vector< std::pair< std::uint32_t, std::uint32_t > > dest;
  for( const auto &p: temp ) {
    if( !p.empty() ) {
      std::uint32_t parent = p[ 0 ] - 1u;
      for( unsigned int i = 1u; i != p.size(); ++i ) {
        dest.emplace_back( parent, p[ i ] - 1u );
      }
    }
  }
  return dest; 
}

}

