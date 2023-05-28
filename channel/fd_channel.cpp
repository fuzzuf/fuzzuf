#include "fuzzuf/channel/fd_channel.hpp"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/errno_to_system_error.hpp"
#include "fuzzuf_cc/fork_server_api.h"

namespace fuzzuf::channel {

FdChannel::FdChannel() {
  // Nothing to do
}

FdChannel::~FdChannel() { TerminateForkServer(); }

// Write exact `size` bytes
ssize_t FdChannel::Send(void *buf, size_t size, const char *comment) {
  ssize_t nbytes = fuzzuf::utils::write_n(forksrv_write_fd, buf, size);
  if (nbytes < (ssize_t)size) {
    throw fuzzuf::utils::errno_to_system_error(
        errno, fuzzuf::utils::StrPrintf("[FdChannel] Failed to send: %s "
                                        "(Requested %ld bytes, Sent %ld bytes)",
                                        comment, size, nbytes));
  }
  return nbytes;
}

// Read exact `size` bytes
// Recieved data to be stored to user allocated pointer `buf`
ssize_t FdChannel::Recv(void *buf, size_t size, const char *comment) {
  ssize_t nbytes = fuzzuf::utils::read_n(forksrv_read_fd, buf, size, true);
  if (nbytes < (ssize_t)size) {
    throw fuzzuf::utils::errno_to_system_error(
        errno,
        fuzzuf::utils::StrPrintf("[FdChannel] Failed to recieve: %s (Requested "
                                 "%d bytes, Recieved %d bytes)",
                                 comment, size, nbytes));
  }
  return nbytes;
}

// PUT API
// NOTE: 現在PUTが実行を終了するまで待つブロッキングな実装になっています
//  Persistent mode
//  だとプロセスが止まってfuzzerからの指示を待つらしいのでこれは実装不備
// FIXME: fuzzuf-ccは4バイト以上読み取れなかったら forkserver
// プロセスが終了する実装になっています。
//  そのとき、FdChannelはforkserverは生きていると思っていて、APIの返答を待つ。これはまずい。
ExecutePUTAPIResponse FdChannel::ExecutePUT() {
  ForkServerAPI command = ExecutePUTCommand;
  Send((void *)&command, sizeof(command), __func__);

  ExecutePUTAPIResponse response;
  Recv((void *)&response, sizeof(response), __func__);

  DEBUG("Response { error=%d, exit_code=%d, signal_number=%d }", response.error,
        response.exit_code, response.signal_number);
  assert(response.error == ExecutePUTError::None);

  return response;
}

// PUT API
// If timeout_us is 0, then time limit is unlimited.
void FdChannel::SetPUTExecutionTimeout(uint64_t timeout_us /* [us] */) {
  DEBUG("SetPUTExecutionTimeout: timeout_us=%ld", timeout_us);
  ForkServerAPI command = SetPUTExecutionTimeoutCommand;
  Send((void *)&command, sizeof(command), __func__);
  Send(&timeout_us, sizeof(timeout_us), "PUTExecutionTimeoutValue");
  // NOTE: No response
}

// PUT API
void FdChannel::ReadStdin() {
  DEBUG("ReadStdin: Enabled");
  ForkServerAPI command = ReadStdinCommand;
  Send((void *)&command, sizeof(command), __func__);
  // NOTE: No response
}

// PUT API
void FdChannel::SaveStdoutStderr() {
  DEBUG("SaveStdoutStderr: Enabled");
  ForkServerAPI command = SaveStdoutStderrCommand;
  Send((void *)&command, sizeof(command), __func__);
  // NOTE: No response
}

void FdChannel::AttachToServer(uint64_t executor_id) {
  if (write(forksrv_write_fd, &executor_id, sizeof(executor_id)) <
      (ssize_t)sizeof(executor_id)) {
    perror("[!] [FdChannel] Failed to attach to server");
    exit(1);
  }
  fprintf(stderr,
          "[*] [FdChannel] Requested server to attach: executor_id=%lu\n",
          executor_id);
}

std::optional<pid_t> FdChannel::WaitForkServerStart() {
  pid_t forksrv_pid = 0;
  try {
    Recv(&forksrv_pid, sizeof(forksrv_pid), __func__);
  } catch (const std::system_error &e) {
    MSG(cLRD "[-] " cRST "    %s\n", e.what());
    return std::nullopt;
  }
  DEBUG("[FdChannel] Forkserver started: pid=%d\n", forksrv_pid);
  return forksrv_pid;
}

// Helper function to assure forkserver is up
std::optional<pid_t> FdChannel::DoHandShake(uint64_t executor_id) {
  AttachToServer(executor_id);
  return WaitForkServerStart();
}

// PUT API
void FdChannel::SetupForkServer(char *const pargv[],
                                const std::vector<const char *> &envp) {
  raw_environment_variables = envp;
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

    // FIXME:
    // 無条件で標準（エラ）出力をクローズ。標準入出力を記録する機能が死んでいるのはフェーズ3で直す
    int null_fd = fuzzuf::utils::OpenFile("/dev/null", O_RDONLY | O_CLOEXEC);
    int stdout_fd = dup(STDOUT_FILENO);
    int stderr_fd = dup(STDERR_FILENO);
    fcntl(stdout_fd, F_SETFD, O_CLOEXEC);
    fcntl(stderr_fd, F_SETFD, O_CLOEXEC);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);

    execve(pargv[0], pargv,
           const_cast<char **>(raw_environment_variables.data()));

    /* Execution failed */
    dup2(stdout_fd, STDOUT_FILENO);
    dup2(stderr_fd, STDERR_FILENO);
    ERROR("execv() failed");
  }

  close(par2chld[0]);
  close(chld2par[1]);

  forksrv_write_fd = par2chld[1];
  forksrv_read_fd = chld2par[0];

  // Handshakes with forkserver
  // Our goal is to distinguish following four cases:
  //  - (1) Correctly instrumented
  //  - (2) No instrumentation and no output
  //  - (3) Not instrumented, no output or immediate termination
  //  - (4) It's not instrumented and it outputs something (which is received
  //  during the handshake).
  if (DoHandShake((uint64_t)getpid()) != forksrv_pid) {
    // If case (2) and (3) occurs, then WaitForkServerStart() returns
    // std::nullopt If case (4) occurs, then return value won't be equal to
    // forksrv_pid

    /* Invalid instrumentation detected or PUT execution failed */
    int status = 0;
    waitpid(forksrv_pid, &status, WNOHANG);

    if (WSTOPSIG(status)) {
      // Met case (3)
      /* Show error message in case PUT is not instrumented
         and exits immediately with non-zero status code */
      ERROR("Failed to execute PUT (exited)");
      exit(1);
    } else {
      // Met case (2) or (4)
      /* If child process is alive, instrumentation is invalid */
      MSG(cLRD "[-] " cRST
               "    Looks like the target binary is not instrumented by "
               "fuzzuf-cc!\n");
      ERROR("No valid instrumentation detected");
    }
  }
  // Reaching here meets case (1). Let's start fuzzing!

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

}  // namespace fuzzuf::channel
