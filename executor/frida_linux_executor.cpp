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
#include "fuzzuf/executor/frida_linux_executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include <boost/logic/tribool.hpp>
#include <chrono>
#include <cstddef>
#include <cassert>
#include <cstdlib>
#include <memory>
#include <optional>
#include <boost/container/static_vector.hpp>
#include <sched.h>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/which.hpp"
#include "fuzzuf/utils/is_executable.hpp"
#include "fuzzuf/utils/interprocess_shared_object.hpp"
#include "fuzzuf/utils/errno_to_system_error.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "config.h"

/**
 * Precondition:
 *   - A file can be created at path path_str_to_write_input.
 * Postcondition:
 *     - Run process below in order, with initializing members
 *       * Configure signal handlers (Temporary workaround for non fork server mode. This will be removed in future.)
 *       * Parsing and preprocessing of commandline arguments of PUT.
 *       * Generate a file for sending input to  PUT.
 *       * Configure shared memory
 *         - afl_shm_size should indicate the size of shared memory which PUT built using AFL style cc uses.
 *         - bb_shm_size should indicate the size of shared memory that is used to record Basic Block Coverage by PUT built using fuzzuf-cc.
 *         - If both parameters are set to zero, it is considered as unused, and never allocate.
 *         - In kernel, Both parameters are round up to multiple of PAGE_SIZE, then memory is allocated.
 *       * Configure environment variables for PUT
 *       * If fork server mode, launch fork server.
 *       * NOTE: Executor does not take care about binding a CPU core. The owner fuzzing algorithm is responsible to it.
 */
FridaLinuxExecutor::FridaLinuxExecutor(
    const std::vector<std::string>& argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    bool forksrv,
    const fs::path& path_to_write_input,
    u32 afl_shm_size,
    u32 bb_shm_size,
    bool record_stdout_and_err
) : NativeLinuxExecutor(
        argv, exec_timelimit_ms, exec_memlimit,
        forksrv ? deferred : static_cast<tribool>(false),
        path_to_write_input, afl_shm_size, bb_shm_size, record_stdout_and_err)
{
    struct stat statbuf;
    if ((stat(FUZZUF_AFL_FRIDA_TRACE_SO, &statbuf)) == -1) {
        ERROR("A file afl-frida-trace.so not found. Please specify the path with -DAFL_ROOT on cmake");
    }
    setenv("LD_PRELOAD", FUZZUF_AFL_FRIDA_TRACE_SO, 1);
    // Need to add the size of the library
    this->exec_memlimit += (statbuf.st_size >> 20);

    MSG(cCYA "before: %s\n" cRST, getenv("__AFL_DEFER_FORKSRV"));
    setenv("__AFL_DEFER_FORKSRV", "1", 1);
    MSG(cCYA "after : %s\n" cRST, getenv("__AFL_DEFER_FORKSRV"));
    if (forksrv) {
        // Finally start the fork-server setup
        NativeLinuxExecutor::SetupForkServer();
    }
}

FridaLinuxExecutor::~FridaLinuxExecutor()
{
    NativeLinuxExecutor::~NativeLinuxExecutor();
}
void FridaLinuxExecutor::Run(const u8 *buf, u32 len, u32 timeout_ms)
{
    NativeLinuxExecutor::Run(buf, len, timeout_ms);
}
void FridaLinuxExecutor::ReceiveStopSignal(void)
{
    NativeLinuxExecutor::ReceiveStopSignal();
}

