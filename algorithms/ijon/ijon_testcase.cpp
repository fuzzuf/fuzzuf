#include "fuzzuf/algorithms/ijon/ijon_testcase.hpp"

namespace fuzzuf::algorithm::ijon {

IJONTestcase::IJONTestcase(std::shared_ptr<OnDiskExecInput> input)
    : AFLTestcase(input) {}

IJONTestcase::~IJONTestcase() {}

} // namespace fuzzuf::algorithm::ijon
