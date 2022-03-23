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
#include <sys/epoll.h>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/coverage/afl_edge_cov_attacher.hpp"
#include "fuzzuf/coverage/fuzzuf_bb_cov_attacher.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"

// A class for fuzz execution under native Linux environment (i.e. the Linux environment where the fuzzer tracer and the fuzz target are the same)
//
// Responsibility:
//  - Class member Executor::argv must hold the information required for an execution of the fuzzing target process (e.g. command, arguments)
//
// Responsibility (TODO):
//  - The lifetime for the class itself and the time period of validity of member variables must match (TODO because checks have not completed)
//      - This is to ensure the robustness
class FridaLinuxExecutor : public NativeLinuxExecutor {
public:
    FridaLinuxExecutor(  
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        bool forksrv,
        const fs::path &path_to_write_input,
        u32 afl_shm_size,
        u32  bb_shm_size,
        const fs::path &proxy_path,
        // FIXME: The below is a temporary flag to avoid a big performance issue.
        // The issue appears when we save the outputs of stdout/stderr to buffers
        // in every execution of a PUT, which isn't required in most fuzzers.
        // This is just a temporary and ugly countermeasure.
        // In the future, we should generalize this flag so that we can arbitrarily specify 
        // which fd should be recorded. For example, by passing std::vector<int>{1, 2} to this class,
        // we would tell that we would like to record stdout and stderr.
        bool record_stdout_and_err = false,
        std::vector<std::string> &&environment_variabels_ = {}
    );
    ~FridaLinuxExecutor() override;

    FridaLinuxExecutor( const FridaLinuxExecutor& ) = delete;
    FridaLinuxExecutor( FridaLinuxExecutor&& ) = delete;
    FridaLinuxExecutor &operator=( const FridaLinuxExecutor& ) = delete;
    FridaLinuxExecutor &operator=( FridaLinuxExecutor&& ) = delete;
    FridaLinuxExecutor() = delete;

    void Run(const u8 *buf, u32 len, u32 timeout_ms=0) override;
    void ReceiveStopSignal(void) override;
};
