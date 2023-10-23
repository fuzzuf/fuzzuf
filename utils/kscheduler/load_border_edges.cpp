#include <fcntl.h>
#include <vector>
#include <utility>
#include <cstdint>
#include <boost/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/fusion/container/vector.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/map_file.hpp>
#include <fuzzuf/utils/kscheduler/load_katz_centrality.hpp>

namespace fuzzuf::utils::kscheduler {

std::vector< std::pair< std::uint32_t, std::uint32_t > >
LoadBorderEdges(
  const fs::path &filename
) {
  const auto range = map_file( filename.string(), O_RDONLY, true );
  auto iter = range.begin();
  const auto end = range.end();
  std::vector< boost::fusion::vector< std::uint32_t, std::uint32_t > > temp;
  namespace qi = boost::spirit::qi;
  if (!qi::parse(iter, end,
                 qi::skip( qi::standard::blank )[ qi::uint_ >> qi::uint_ ] % qi::eol >> qi::omit[ *qi::standard::space ],
                 temp) ||
      iter != end) {
    throw exceptions::invalid_argument( std::string( "fuzzuf::utils::LoadBorderEdges : " ) + filename.string() + " : The file is broken", __FILE__, __LINE__ );
  }
  std::vector< std::pair< std::uint32_t, std::uint32_t > > dest;
  dest.reserve( temp.size() );
  std::transform(
    temp.begin(),
    temp.end(),
    std::back_inserter( dest ),
    []( const auto &v ) {
      return std::make_pair(
        boost::fusion::at_c< 0 >( v ) - 1u,
	boost::fusion::at_c< 1 >( v ) - 1u
      );
    }
  );
  return dest; 
}

}

