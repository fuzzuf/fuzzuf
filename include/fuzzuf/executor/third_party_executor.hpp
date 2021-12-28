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
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/file_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"

class ThirdPartyExecutor : public Executor {
public:

    const std::string path_str_to_tool_exec;
    const std::vector<std::string> targv;

    bool child_timed_out;


    static ThirdPartyExecutor *active_instance;

    static bool has_setup_sighandlers;

    ThirdPartyExecutor(  
        const fs::path &path_to_tool_exec,
        const std::vector<std::string> &targv,
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        const fs::path &path_to_write_input
    );

    ThirdPartyExecutor(  
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        const fs::path &path_to_write_input
    );
    ~ThirdPartyExecutor();

    ThirdPartyExecutor( const ThirdPartyExecutor& ) = delete;
    ThirdPartyExecutor( ThirdPartyExecutor&& ) = delete;
    ThirdPartyExecutor &operator=( const ThirdPartyExecutor& ) = delete;
    ThirdPartyExecutor &operator=( ThirdPartyExecutor&& ) = delete;
    ThirdPartyExecutor() = delete;

    void Initilize();
    void Run(const u8 *buf, u32 len, u32 timeout_ms=0);
    void ReceiveStopSignal(void);

    // Environment-specific methods
    FileFeedback GetFileFeedback(fs::path feed_path);
    ExitStatusFeedback GetExitStatusFeedback();

    virtual void SetCArgvAndDecideInputMode(){};

    static void SetupSignalHandlers();
    static void AlarmHandler(int signum);

private:    
    PUTExitReasonType last_exit_reason;
    u8 last_signal;      
};
