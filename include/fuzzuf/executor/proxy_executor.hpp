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
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/file_feedback.hpp"

// A class for fuzz execution under Linux environment through proxies (such as QEMU) having fork server.
//
// Responsibility:
//  - Class member Executor::argv must hold the information required for an execution of the fuzzing target process (e.g. command, arguments)
//  - A class member ProxyExecutor::proxy_path must hold the path to the proxy which is going to be executed
//  - A class member ProxyExecutor::pargv must hold the information required for an execution of the proxy (e.g. arguments)
//
// Responsibility (TODO):
//  - The lifetime for the class itself and the time period of validity of member variables must match (TODO because checks have not completed)
//      - This is to ensure the robustness
class ProxyExecutor : public Executor {
public:
    static constexpr u32 EXEC_FAIL_SIG = 0xfee1dead;
    /* Distinctive exit code used to indicate MSAN trip condition: */
    static constexpr u32 MSAN_ERROR    =         86;

    static constexpr int INVALID_SHMID = -1; 

    static constexpr int FORKSRV_FD_READ  = 198;
    static constexpr int FORKSRV_FD_WRITE = 199;

    static constexpr const char* AFL_SHM_ENV_VAR = "__AFL_SHM_ID";
    // FIXME: we have to modify fuzzuf-cc to change __WYVERN_SHM_ID to __FUZZUF_SHM_ID
    static constexpr const char* FUZZUF_SHM_ENV_VAR = "__WYVERN_SHM_ID";

    // Members holding settings handed over a constructor
    const fs::path proxy_path;
    const std::vector<std::string> pargv;
    const bool forksrv;

    // FIXME: we want to change the type of these variables to u64.
    // But to do this, we have to modify InplaceFeedback and everything using it.
    const u32  afl_shm_size;
    const u32   bb_shm_size;

    const bool uses_asan = false; // May become one of the available options in the future, but currently not anticipated

    // ProxyExecutor::INVALID_SHMID means not holding valid ID
    int bb_shmid;  
    int afl_shmid; 

    int forksrv_pid;
    int forksrv_read_fd;
    int forksrv_write_fd;

    u8 *bb_trace_bits;
    u8 *afl_trace_bits;

    bool child_timed_out;

    static bool has_setup_sighandlers;
    // A pointer to a currently active instance, used by a signal handler.
    // nullptr if no such instance.
    // Beware that it temporarily assumes that multiple fuzzer instances do not become active simultaneously.
    static ProxyExecutor *active_instance;

    ProxyExecutor(
        const fs::path &proxy_path,
        const std::vector<std::string> &pargv,
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        bool forksrv,
        const fs::path &path_to_write_input,
        u32 afl_shm_size,
        u32  bb_shm_size,
        // FIXME: The below is a temporary flag to avoid a big performance issue.
        // The issue appears when we save the outputs of stdout/stderr to buffers
        // in every execution of a PUT, which isn't required in most fuzzers.
        // This is just a temporary and ugly countermeasure.
        // In the future, we should generalize this flag so that we can arbitrarily specify 
        // which fd should be recorded. For example, by passing std::vector<int>{1, 2} to this class,
        // we would tell that we would like to record stdout and stderr.
        bool record_stdout_and_err = false
    );
    ProxyExecutor(
        const fs::path &proxy_path,
        const std::vector<std::string> &pargv,
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        const fs::path &path_to_write_input
    );
    ProxyExecutor(
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        const fs::path &path_to_write_input
    );
    ~ProxyExecutor();

    ProxyExecutor( const ProxyExecutor& ) = delete;
    ProxyExecutor( ProxyExecutor&& ) = delete;
    ProxyExecutor &operator=( const ProxyExecutor& ) = delete;
    ProxyExecutor &operator=( ProxyExecutor&& ) = delete;
    ProxyExecutor() = delete;

    // Common methods among children on Executor classes
    // Declare in the base class and define in each derivative, if possible (how to achieve?)
    void Initilize();
    void Run(const u8 *buf, u32 len, u32 timeout_ms=0);
    void ReceiveStopSignal(void);

    // Environment-specific methods
    InplaceMemoryFeedback GetAFLFeedback();
    InplaceMemoryFeedback GetBBFeedback();
    InplaceMemoryFeedback GetStdOut();
    InplaceMemoryFeedback GetStdErr();
    FileFeedback GetFileFeedback(fs::path feed_path);
    ExitStatusFeedback GetExitStatusFeedback();

    void TerminateForkServer();
    virtual void SetCArgvAndDecideInputMode();
    virtual void SetupSharedMemories();
    virtual void ResetSharedMemories();
    virtual void EraseSharedMemories();
    virtual void SetupEnvironmentVariablesForTarget();
    void SetupForkServer();    

    static void SetupSignalHandlers();
    static void AlarmHandler(int signum);

    // InplaceMemoryFeedback made of GetStdOut before calling this function becomes invalid after Run()
    fuzzuf::executor::output_t MoveStdOut();
    // InplaceMemoryFeedback made of GetStdErr before calling this function becomes invalid after Run()
    fuzzuf::executor::output_t MoveStdErr();

protected:
    bool record_stdout_and_err;
    bool has_shared_memories;

private:
    PUTExitReasonType last_exit_reason;
    u8 last_signal;    
    fuzzuf::executor::output_t stdout_buffer;
    fuzzuf::executor::output_t stderr_buffer;
    int fork_server_stdout_fd = -1;
    int fork_server_stderr_fd = -1;
    int fork_server_epoll_fd = -1;
    epoll_event fork_server_stdout_event;
    epoll_event fork_server_stderr_event;
    epoll_event fork_server_read_event;
};
