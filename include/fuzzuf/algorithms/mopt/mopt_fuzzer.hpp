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

#pragma once

#include <vector>
#include <string>

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/mopt/mopt_state.hpp"

namespace fuzzuf::algorithm::mopt {

class MOptFuzzer : public afl::AFLFuzzerTemplate<MOptState> {
public:
    explicit MOptFuzzer(std::unique_ptr<MOptState>&& state);
    ~MOptFuzzer();

    void BuildFuzzFlow(void) override;
    void OneLoop(void) override;

private:
    bool MOptShouldSchedule(void);
};

} // namespace fuzzuf::algorithm::mopt
