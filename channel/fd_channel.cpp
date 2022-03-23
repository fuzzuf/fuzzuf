#include "fuzzuf/channel/fd_channel.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/errno_to_system_error.hpp"

#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

FdChannel::FdChannel() {
    // Nothing to do
}

FdChannel::~FdChannel() {
    TerminateForkServer();
}

// Write exact `size` bytes
ssize_t FdChannel::Send(void *buf, size_t size, const char* comment) {
    ssize_t nbytes = Util::write_n(forksrv_write_fd, buf, size);
    if (nbytes < (ssize_t) size) {
        throw fuzzuf::utils::errno_to_system_error(
            errno, Util::StrPrintf("[FdChannel] Failed to send: %s (Requested %d bytes, Sent %d bytes)", comment, size, nbytes));
    }
    return nbytes;
}

// Read exact `size` bytes
// Recieved data to be stored to user allocated pointer `buf`
ssize_t FdChannel::Recv(void *buf, size_t size, const char* comment) {
    ssize_t nbytes = Util::read_n(forksrv_read_fd, buf, size, true);
    if (nbytes < (ssize_t) size) {
        throw fuzzuf::utils::errno_to_system_error(
            errno, Util::StrPrintf("[FdChannel] Failed to recieve: %s (Requested %d bytes, Recieved %d bytes)", comment, size, nbytes));
    }
    return nbytes;
}

// PUT API
// NOTE: 現在PUTが実行を終了するまで待つブロッキングな実装になっています
//  Persistent mode だとプロセスが止まってfuzzerからの指示を待つらしいのでこれは実装不備
// FIXME: fuzzuf-ccは4バイト以上読み取れなかったら forkserver プロセスが終了する実装になっています。
//  そのとき、FdChannelはforkserverは生きていると思っていて、APIの返答を待つ。これはまずい。
ExecutePUTAPIResponse FdChannel::ExecutePUT() {
    Send((void *) "ExecutePUT", 10, __func__);

    ExecutePUTAPIResponse response;
    Recv((void *) &response, sizeof(response), __func__);

    DEBUG("Response { error=%d, exit_code=%d, signal_number=%d }", 
        response.error, response.exit_code, response.signal_number);
    // TODO: fork_server_stdout_fd, fork_server_stderr_fd からのデータ読み取り（フェーズ3預かり）
    assert(response.error == ExecutePUTError::None);

    return response;
}

// Helper function to assure forkserver is up
pid_t FdChannel::WaitForkServerStart() {
    pid_t forksrv_pid = 0;
    Recv(&forksrv_pid, sizeof(forksrv_pid), __func__);
    DEBUG("Forkserver started: pid=%d\n", forksrv_pid);
    return forksrv_pid;
}

// PUT API
void FdChannel::SetupForkServer(char *const pargv[]) {
    DEBUG("[*] [FdChannel] SetupForkserver");

    if (!fs::exists(pargv[0])) {
        ERROR("PUT does not exists: %s", pargv[0]);
    }

    int par2chld[2], chld2par[2];

    if (pipe(par2chld) || pipe(chld2par)) {
        ERROR("pipe() failed");
    }

    forksrv_pid = fork();
    if (forksrv_pid < 0) {
        ERROR("fork() failed");
    }

    if (forksrv_pid == 0) {
        // In PUT process
        if (dup2(par2chld[0], FORKSRV_FD_READ) < 0) {
            ERROR("dup2() failed");
        };
        if (dup2(chld2par[1], FORKSRV_FD_WRITE) < 0) {
            ERROR("dup2() failed");
        }

        close(par2chld[0]);
        close(par2chld[1]);
        close(chld2par[0]);
        close(chld2par[1]);
        DEBUG("[*] [FdChannel] pargv[0]=\"%s\": pid=%d\n", pargv[0], getpid());

        // FIXME: 無条件で標準（エラ）出力をクローズ。標準入出力を記録する機能が死んでいるのはフェーズ3で直す
        int null_fd = Util::OpenFile("/dev/null", O_RDONLY | O_CLOEXEC);
        int stdout_fd = dup(STDOUT_FILENO);
        int stderr_fd = dup(STDERR_FILENO);
        fcntl(stdout_fd, F_SETFD, O_CLOEXEC);
        fcntl(stderr_fd, F_SETFD, O_CLOEXEC);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);

        execv(pargv[0], pargv);

        /* Execution failed */
        dup2(stdout_fd, STDOUT_FILENO);
        dup2(stderr_fd, STDERR_FILENO);
        ERROR("execv() failed");
    }

    close(par2chld[0]);
    close(chld2par[1]);

    forksrv_write_fd = par2chld[1];
    forksrv_read_fd = chld2par[0];

    if (WaitForkServerStart() != forksrv_pid) {
        /* Invalid instrumentation detected or PUT execution failed */
        int status = 0;
        waitpid(forksrv_pid, &status, WNOHANG);

        if (WSTOPSIG(status)) {
            /* Show error message in case PUT is not instrumented
               and exits immediately with non-zero status code */
            ERROR("Failed to execute PUT (exited)");
            exit(1);
        } else {
            /* If child process is alive, instrumentation is invalid */
            MSG(cLRD "[-] " cRST
                "    Looks like the target binary is not instrumented by fuzzuf-cc!\n");
            ERROR("No valid instrumentation detected");
        }
    }

    return;
}

// PUT API
/**
 * Stop fork server, then delete relevant values properly.
 * Postcondition:
 *  - If forksrv_{read,write}_fd have valid values,
 *      - Close them
 *      - invalidate the values(fail-safe)
 *  - If forksrv_pid has valid value,
 *      - Terminate the process identified by forksrv_pid
 *      - Reap the process terminating using waitpid
 *      - Furthermore, invalidate the value of forksrv_pid(fail-safe)
 */
void FdChannel::TerminateForkServer() {
    // if (fork_server_stdout_fd != -1) {
    //     close( fork_server_stdout_fd );
    //     fork_server_stdout_fd = -1;
    // }
    
    // if (fork_server_stderr_fd != -1) {
    //     close( fork_server_stderr_fd );
    //     fork_server_stderr_fd = -1;
    // }

    if (forksrv_write_fd > 0) {
        close(forksrv_write_fd);
        forksrv_write_fd = -1;
    }
    if (forksrv_read_fd > 0) {
        close(forksrv_read_fd);
        forksrv_read_fd = -1;
    }

    if (forksrv_pid > 0) {
        int status;
        kill(forksrv_pid, SIGKILL);
        waitpid(forksrv_pid, &status, 0);
        forksrv_pid = -1;
    }
}