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
#include <cstddef>
#include <cassert>
#include <memory>
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/executor/pintool_executor.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"

PinToolExecutor::PinToolExecutor(  
    const fs::path &path_to_tool_exec,
    const std::vector<std::string> &targv,             
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    const fs::path &path_to_write_input    
) :
    ThirdPartyExecutor( path_to_tool_exec, targv, argv, exec_timelimit_ms, exec_memlimit, path_to_write_input)
{    
    SetCArgvAndDecideInputMode();
}

void PinToolExecutor::SetCArgvAndDecideInputMode() {
    assert(!argv.empty());
    
    stdin_mode = true; // if we find @@, then assign false to stdin_mode

    cargv.emplace_back(path_str_to_tool_exec.c_str());
    cargv.emplace_back("-t");

    for (const auto& v : targv ) {
        cargv.emplace_back(v.c_str());
    }
    
    cargv.emplace_back("--");

    for (const auto& v : argv ) {
        if ( v == "@@" ) {
            stdin_mode = false;
            cargv.emplace_back(path_str_to_write_input.c_str());
        } else {
            cargv.emplace_back(v.c_str());
        }
    }
    cargv.emplace_back(nullptr);
}
