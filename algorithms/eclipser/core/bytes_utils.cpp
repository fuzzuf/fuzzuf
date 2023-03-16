#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/bytes_utils.hpp>

namespace fuzzuf::algorithm::eclipser {

void to_json( nlohmann::json &dest, Endian src ) {
  if( src == Endian::LE ) {
    dest = "LE";
  }
  else if( src == Endian::BE ) {
    dest = "BE";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Endian &dest ) {
  if( src.is_string() ) {
    if( src == "LE" ) {
      dest = Endian::LE;
    }
    else if( src == "BE" ) {
      dest = Endian::BE;
    }
    else {
      dest = Endian::LE;
    }
  }
  else if( src.is_number() ) {
    dest = Endian( int( src ) );
  }
  else {
    dest = Endian::LE;
  }
}


std::vector< std::byte >
BigIntToBytes( Endian endian, std::size_t size, BigInt value ) {
  std::vector< std::byte > temp;
  for( std::size_t i = 0u; i != size; ++i ) {
    temp.push_back( std::byte( std::uint8_t( value ) ) );
    value >>= 8;
  }
  if( endian == Endian::BE ) {
    std::reverse( temp.begin(), temp.end() );
  }
  return temp;
}

BigInt BytesToBigInt( Endian endian, const std::vector< std::byte > &bytes ) {
  BigInt v;
  if( endian == Endian::LE ) {
    for( auto iter = bytes.rbegin(); iter != bytes.rend(); ++iter ) {
      v <<= 8;
      v += uint32_t( *iter );
    }
  }
  else {
    for( auto iter = bytes.begin(); iter != bytes.end(); ++iter ) {
      v <<= 8;
      v += uint32_t( *iter );
    }
  }
  return v;
}

}

