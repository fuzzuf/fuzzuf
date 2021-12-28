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
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/executor/third_party_executor.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"

bool ThirdPartyExecutor::has_setup_sighandlers = false;

ThirdPartyExecutor* ThirdPartyExecutor::active_instance = nullptr;

void ThirdPartyExecutor::Initilize()
{
    if (!has_setup_sighandlers) {
        SetupSignalHandlers();
        has_setup_sighandlers = true;
    }

    active_instance = this;
    
    OpenExecutorDependantFiles();
}

ThirdPartyExecutor::ThirdPartyExecutor(  
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    const fs::path &path_to_write_input
) :
    Executor( argv, exec_timelimit_ms, exec_memlimit, path_to_write_input.string() ),
    path_str_to_tool_exec( "" )
{
    Initilize();
}

ThirdPartyExecutor::ThirdPartyExecutor(  
    const fs::path &path_to_tool_exec,
    const std::vector<std::string> &targv,
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    const fs::path &path_to_write_input
) :
    Executor( argv, exec_timelimit_ms, exec_memlimit, path_to_write_input.string() ),
    path_str_to_tool_exec( path_to_tool_exec.string() ),    
    targv( targv ),
    child_timed_out( false )
{
    Initilize();
}

ThirdPartyExecutor::~ThirdPartyExecutor() {
    if (input_fd != -1) {
        Util::CloseFile(input_fd);
        input_fd = -1;
    }
    if (null_fd != -1) {
        Util::CloseFile(null_fd);
        null_fd = -1;
    }    
}

void ThirdPartyExecutor::AlarmHandler(int signum) {
    assert (signum == SIGALRM);
    assert (active_instance != nullptr);
    active_instance->KillChildWithoutWait();
    active_instance->child_timed_out = true;
}

void ThirdPartyExecutor::SetupSignalHandlers() {
    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

#if 0
    /* Various ways of saying "stop". */

    sa.sa_handler = handle_stop_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Window resize */

    sa.sa_handler = handle_resize;
    sigaction(SIGWINCH, &sa, NULL);

    /* SIGUSR1: skip entry */

    sa.sa_handler = handle_skipreq;
    sigaction(SIGUSR1, &sa, NULL);
#endif

    /* Things we don't care about. */

    sa.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = ThirdPartyExecutor::AlarmHandler;
    sigaction(SIGALRM, &sa, NULL);
}

void ThirdPartyExecutor::Run(const u8 *buf, u32 len, u32 timeout_ms) {
    // locked until std::shared_ptr<u8> lock is used in other places
    while (lock.use_count() > 1) {
        usleep(100);
    }

    // if timeout_ms is 0, then we use exec_timelimit_ms;
    if (timeout_ms == 0) timeout_ms = exec_timelimit_ms;
    
    WriteTestInputToFile(buf, len);

    //#if 0
    DEBUG("Run: ");
    std::for_each( cargv.begin(), cargv.end(), []( const char* v ) { DEBUG("%s ", v); } );
    DEBUG("\n")
    //#endif
  
    child_pid = Util::Fork();
    if (child_pid < 0) ERROR("fork() failed");
    if (!child_pid) {

        struct rlimit r;
        if (exec_memlimit) {
            r.rlim_max = r.rlim_cur = ((rlim_t)exec_memlimit) << 20;
        #ifdef RLIMIT_AS
            setrlimit(RLIMIT_AS, &r); /* Ignore errors */
        #else
            setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
        #endif /* ^RLIMIT_AS */
        }

        r.rlim_max = r.rlim_cur = 0;

        setrlimit(RLIMIT_CORE, &r); /* Ignore errors */
            
        /* Isolate the process and configure standard descriptors. If out_file is
            specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
        setsid();

        dup2(null_fd, 1);
        dup2(null_fd, 2);

        if (stdin_mode) {
            dup2(input_fd, 0);
        } else {
            dup2(null_fd, 0);
        }
        execv(cargv[0], (char**)cargv.data());

        exit(0);
    }

    int put_status; // PUT's status(retrieved via waitpid)
    child_timed_out = false;    //TODO: 

    static struct itimerval it;

    if (exec_timelimit_ms) {
        it.it_value.tv_sec = (timeout_ms / 1000);
        it.it_value.tv_usec = (timeout_ms % 1000) * 1000;
        setitimer(ITIMER_REAL, &it, NULL);
    }

    if (waitpid(child_pid, &put_status, 0) <= 0) ERROR("waitpid() failed");

    if (exec_timelimit_ms) {        
        it.it_value.tv_sec = 0;
        it.it_value.tv_usec = 0;
        setitimer(ITIMER_REAL, &it, NULL);
    }

    if (!WIFSTOPPED(put_status)) child_pid = 0; 
    DEBUG("Exec Status %d (pid %d)\n", put_status, child_pid);

    /* Any subsequent operations on trace_bits must not be moved by the
        compiler below this point. Past this location, trace_bits[] behave
        very normally and do not have to be treated as volatile. */

    MEM_BARRIER();

    last_exit_reason = PUTExitReasonType::FAULT_NONE;
    last_signal = 0;

    /* Report outcome to caller. */
    if (WIFSIGNALED(put_status)) {
        last_signal = WTERMSIG(put_status);
        
        if (child_timed_out && last_signal == SIGKILL)
            last_exit_reason = PUTExitReasonType::FAULT_TMOUT;
        else 
            last_exit_reason = PUTExitReasonType::FAULT_CRASH;
 
        return ;
    }

    last_exit_reason = PUTExitReasonType::FAULT_NONE;    
    return;    
}

FileFeedback ThirdPartyExecutor::GetFileFeedback(fs::path feed_path) {
    return FileFeedback(feed_path, lock);
}

ExitStatusFeedback ThirdPartyExecutor::GetExitStatusFeedback() {
    return ExitStatusFeedback(last_exit_reason, last_signal);
}

// this function may be called in signal handlers.
// use only async-signal-safe functions inside.
// basically, we care about only the case where ThirdPartyExecutor::Run is running.
// in that case, we should kill the child process(of PUT) so that ThirdPartyExecutor could halt without waiting the timeout.
// if this function is called during the call of other functions, then the child process is not active.
// we can call KillChildWithoutWait() anyways because the function checks if the child process is active.
void ThirdPartyExecutor::ReceiveStopSignal(void) {
    // kill is async-signal-safe
    // the child process is active only in ThirdPartyExecutor::Run and Run always uses waitpid, so we don't need to use waitpid here
    KillChildWithoutWait();
}
