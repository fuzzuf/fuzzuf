#include "fuzzuf/algorithms/mopt/mopt_testcase.hpp"

namespace fuzzuf::algorithm::mopt {

MOptTestcase::MOptTestcase(std::shared_ptr<OnDiskExecInput> input)
    : AFLTestcase(input) {}

MOptTestcase::~MOptTestcase() {}

} // namespace fuzzuf::algorithm::mopt
