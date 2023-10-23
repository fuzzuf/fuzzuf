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
