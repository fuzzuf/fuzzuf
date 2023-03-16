#include <cstdlib>
#include <fuzzuf/algorithms/eclipser/core/failwith.hpp>

namespace fuzzuf::algorithm::eclipser {

void failwith( const std::string& ) {
  std::abort();
}

}

