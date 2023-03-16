#include <charconv>
#include <cstddef>
#include <string>
#include <type_traits>
#include <nlohmann/json.hpp>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/algorithms/eclipser/core/byte_val.hpp>
#include <boost/spirit/include/karma.hpp>

namespace fuzzuf::algorithm::eclipser::byteval {

ByteVal NewByteVal( std::byte v ) {
  return Untouched{ v };
}

std::byte GetConcreteByte( ByteVal b ) {
  return std::visit(
    []( const auto &v ) {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Interval > ) {
        return std::byte( ( std::uint16_t( v.low ) + std::uint16_t( v.high ) ) / 2u );
      }
      else {
        return v.value;}
    },
    b
  );
}

bool IsFixed( ByteVal b ) {
  return std::visit(
    []( const auto &v ) {
      return std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Fixed >;
    },
    b
  );
}

bool IsUnfixed( ByteVal b ) {
  return !IsFixed( b );
}

bool IsSampledByte( ByteVal b ) {
  return std::visit(
    []( const auto &v ) {
      return std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Sampled >;
    },
    b
  );
}

bool IsConstrained( ByteVal b ) {
  return std::visit(
    []( const auto &v ) {
      return
        std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Fixed > ||
        std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Interval >;
    },
    b
  );
}

bool IsNullByte( ByteVal b ) {
  return GetConcreteByte( b ) == std::byte( 0u );
}

bool ToHex( char *at, std::uint8_t value ) {
  if( value < 0x10 ) {
    const auto result = std::to_chars( std::next( at, 1 ), std::next( at, 2 ), value, 16 );
    if( result.ec == std::errc{} ) {
      *at = '0';
      return true;
    }
  }
  else {
    const auto result = std::to_chars( at, std::next( at, 2 ), value, 16 );
    if( result.ec == std::errc{} ) {
      return true;
    }
  }
  return false;
}

std::string ToString( ByteVal b ) {
  namespace karma = boost::spirit::karma;
  return std::visit(
    []( const auto &v ) {
      std::array< char, 11u > temp = { 0 };
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Fixed > ) {
        if( !ToHex( temp.data(), std::uint8_t( v.value ) ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
        temp[ 2 ] = '!';
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Interval > ) {
        if( !ToHex( temp.data(), std::uint8_t( std::uint32_t( v.low ) + std::uint32_t( v.high ) )/2u ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
        temp[ 2 ] = '@';
        temp[ 3 ] = '(';
        if( !ToHex( std::next( temp.data(), 4 ), std::uint8_t( v.low ) ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
        temp[ 6 ] = ',';
        if( !ToHex( std::next( temp.data(), 7 ), std::uint8_t( v.high ) ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
        temp[ 9 ] = ')';
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Undecided > ) {
        if( !ToHex( temp.data(), std::uint8_t( v.value ) ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
        temp[ 2 ] = '?';
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Untouched > ) {
        if( !ToHex( temp.data(), std::uint8_t( v.value ) ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Sampled > ) {
        if( !ToHex( temp.data(), std::uint8_t( v.value ) ) ) {
          throw exceptions::unreachable( "serialization unexpectedly failed", __FILE__, __LINE__ );
        }
        temp[ 2 ] = '*';
      }
      return std::string( temp.data() );
    },
    b
  );
}

std::tuple< std::byte, std::byte > GetMinMax( ByteVal b, InputSource input_src ) {
  return std::visit(
    [&]( const auto &v ) {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Fixed > ) {
        return std::make_tuple( v.value, v.value );
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Interval > ) {
        return std::make_tuple( v.low, v.high );
      }
      else {
        return std::visit(
          []( const auto &src ) {
	    return std::make_tuple( std::byte( 0u ), std::byte( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( src ) >, StdInput > ? 127u : 255u ) );
	  },
	  input_src
        );
      }
    },
    b
  );
}


void to_json( nlohmann::json &dest, const ByteVal &src ) {
  dest = std::visit(
    []( const auto &v ) -> nlohmann::json {
      auto root = nlohmann::json::object();
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Fixed > ) {
        root[ "type" ] = "Fixed";
	root[ "value" ] = v.value;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Interval > ) {
        root[ "type" ] = "Interval";
	root[ "low" ] = v.low;
	root[ "high" ] = v.high;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Undecided > ) {
        root[ "type" ] = "Undecided";
	root[ "value" ] = v.value;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Untouched > ) {
        root[ "type" ] = "Untouched";
	root[ "value" ] = v.value;
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, Sampled > ) {
        root[ "type" ] = "Sampled";
	root[ "value" ] = v.value;
      }
      return root;
    },
    src
  );
}

void from_json( const nlohmann::json &src, ByteVal &dest ) {
  if( !src.is_object() ) dest = Fixed();
  else if( src.find( "type" ) == src.end() ) dest = Fixed();
  else if( ( src[ "type" ] == "Fixed" ) && ( src.find( "value" ) != src.end() ) ) {
    dest = Fixed{ src[ "value" ] };
  }
  else if( ( src[ "type" ] == "Interval" ) && ( src.find( "low" ) != src.end() ) && ( src.find( "high" ) != src.end() ) ) {
    dest = Interval{ src[ "low" ], src[ "high" ] };
  }
  else if( ( src[ "type" ] == "Undecided" ) && ( src.find( "value" ) != src.end() ) ) {
    dest = Undecided{ src[ "value" ] };
  }
  else if( ( src[ "type" ] == "Untouched" ) && ( src.find( "value" ) != src.end() ) ) {
    dest = Untouched{ src[ "value" ] };
  }
  else if( ( src[ "type" ] == "Sampled" ) && ( src.find( "value" ) != src.end() ) ) {
    dest = Sampled{ src[ "value" ] };
  }
  else dest = Fixed();
}

}


