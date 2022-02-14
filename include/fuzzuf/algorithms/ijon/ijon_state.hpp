/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_STATE_HPP

#include <vector>
#include <memory>

#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_testcase.hpp"

namespace fuzzuf::algorithm::ijon {

/**
 * @struct
 * expresses the internal state of IJON. 
 * It inherits from AFLStateTemplate to be compatible with AFLState.
 * The lifetime for an instance of this class must be longer than that of HierarFlow.
 */
struct IJONState : public afl::AFLStateTemplate<IJONTestcase> {
    explicit IJONState(std::shared_ptr<const afl::AFLSetting> setting, std::shared_ptr<NativeLinuxExecutor> executor);
    ~IJONState();

    IJONState( const IJONState& ) = delete;
    IJONState& operator=( const IJONState& ) = delete;

    std::vector<u64> max_map = std::vector<u64>(option::GetMaxMapSize<option::IJONTag>());
    // Instead of 
    //    ijon_input_info* infos[MAXMAP_SIZE];
    //    size_t num_entries;
    // define these two vectors:
    std::vector<std::shared_ptr<OnDiskExecInput>> all_inputs;
    std::vector<std::shared_ptr<OnDiskExecInput>> nonempty_inputs;

    size_t num_updates = 0;
    fs::path max_dir;
};

} // namespace fuzzuf::algorithm::ijon

#endif
