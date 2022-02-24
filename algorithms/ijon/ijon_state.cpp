#include "fuzzuf/algorithms/ijon/ijon_state.hpp"

namespace fuzzuf::algorithm::ijon {

IJONState::IJONState(
    std::shared_ptr<const afl::AFLSetting> setting,
    std::shared_ptr<NativeLinuxExecutor> executor
) : 
    afl::AFLStateTemplate<IJONTestcase>(setting, executor) {}

IJONState::~IJONState() {}

} // namespace fuzzuf::algorithm::ijon
