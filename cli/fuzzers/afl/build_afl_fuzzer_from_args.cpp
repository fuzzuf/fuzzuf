#include <iostream>
#include <cstdlib>
#include <boost/program_options.hpp>

namespace fuzzuf::cli::fuzzer::afl {
[[noreturn]] void usage(const boost::program_options::options_description &desc) {
    std::cout << "Help:" << std::endl;
    std::cout << desc << std::endl;
    std::exit(1);
}
}

