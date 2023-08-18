#include "fuzzuf/tests/byte.hpp"

namespace std {

std::ostream &operator<<( std::ostream &stream, std::byte value ) {
  stream << int( value );
  return stream;
}

}

