/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#include <cstddef>
#include <cassert>
#include <memory>
#include <vector>
#include <string>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/executor/third_party_executor.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/file_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"

class PinToolExecutor : public ThirdPartyExecutor {
public:

    PinToolExecutor(  
        const fs::path &path_to_tool_exec,
        const std::vector<std::string> &pargv,             
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        const fs::path &path_to_write_input
    );
    ~PinToolExecutor(){};

    PinToolExecutor( const PinToolExecutor& ) = delete;
    PinToolExecutor( PinToolExecutor&& ) = delete;
    PinToolExecutor &operator=( const PinToolExecutor& ) = delete;
    PinToolExecutor &operator=( PinToolExecutor&& ) = delete;
    PinToolExecutor() = delete;
    
    void SetCArgvAndDecideInputMode();    
};
