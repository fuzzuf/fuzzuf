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
#include <unordered_map>
#include <boost/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/fusion/container/vector.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/map_file.hpp>
#include <fuzzuf/utils/kscheduler/load_katz_centrality.hpp>

namespace fuzzuf::utils::kscheduler {

std::unordered_map< std::uint32_t, double >
LoadKatzCentrality(
  const fs::path &filename
) {
  const auto range = map_file( filename.string(), O_RDONLY, true );
  auto iter = range.begin();
  const auto end = range.end();
  std::vector< boost::fusion::vector< std::uint32_t, double > > temp;
  namespace qi = boost::spirit::qi;
  if (!qi::parse(iter, end,
                 qi::skip( qi::standard::blank )[ qi::uint_ >> qi::double_ ] % qi::eol >> qi::omit[ *qi::standard::space ],
                 temp) ||
      iter != end) {
    throw exceptions::invalid_argument( std::string( "fuzzuf::utils::LoadKatzCentrality : " ) + filename.string() + " : The file is broken", __FILE__, __LINE__ );
  }
  std::unordered_map< std::uint32_t, double > dest;
  std::transform(
    temp.begin(),
    temp.end(),
    std::inserter( dest, dest.end() ),
    []( const auto &v ) {
      return std::make_pair(
        boost::fusion::at_c< 0 >( v ) - 1u,
	boost::fusion::at_c< 1 >( v )
      );
    }
  );
  return dest; 
}

}

