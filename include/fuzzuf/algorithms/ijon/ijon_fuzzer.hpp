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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_FUZZER_HPP

#include <vector>
#include <string>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/ijon/ijon_state.hpp"

namespace fuzzuf::algorithm::ijon {

class IJONFuzzer : public afl::AFLFuzzerTemplate<IJONState> {
public:
    explicit IJONFuzzer(std::unique_ptr<IJONState>&& state);
    ~IJONFuzzer();

    void BuildFuzzFlow(void) override;
    void OneLoop(void) override;

private:
    bool IjonShouldSchedule(void);

    HierarFlowNode<void(void), void(void)> ijon_fuzz_loop;
};

} // namespace fuzzuf::algorithm::ijon

#endif
