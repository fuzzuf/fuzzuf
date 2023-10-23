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

