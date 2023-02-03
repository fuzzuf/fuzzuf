/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
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
#include "fuzzuf/executor/linux_fork_server_executor.hpp"

#include <sched.h>

#include <boost/container/static_vector.hpp>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/check_crash_handling.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/errno_to_system_error.hpp"
#include "fuzzuf/utils/hex_dump.hpp"
#include "fuzzuf/utils/interprocess_shared_object.hpp"
#include "fuzzuf/utils/is_executable.hpp"
#include "fuzzuf/utils/which.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::executor {
/**
 * Precondition:
 *   - A file can be created at path path_str_to_write_input.
 * Postcondition:
 *     - Run process below in order, with initializing members
 *       * Configure signal handlers (Temporary workaround for non fork server
 * mode. This will be removed in future.)
 *       * Parsing and preprocessing of commandline arguments of PUT.
 *       * Generate a file for sending input to  PUT.
 *       * Configure shared memory
 *         - afl_shm_size should indicate the size of shared memory which PUT
 * built using AFL style cc uses.
 *         - bb_shm_size should indicate the size of shared memory that is used
 * to record Basic Block Coverage by PUT built using fuzzuf-cc.
 *         - If both parameters are set to zero, it is considered as unused, and
 * never allocate.
 *         - In kernel, Both parameters are round up to multiple of PAGE_SIZE,
 * then memory is allocated.
 *       * Configure environment variables for PUT
 *       * If fork server mode, launch fork server.
 *       * NOTE: Executor does not take care about binding a CPU core. The owner
 * fuzzing algorithm is responsible to it.
 */
LinuxForkServerExecutor::LinuxForkServerExecutor(
    LinuxForkServerExecutorParameters &&args)
    : Executor(args.argv, args.exec_timelimit_ms, args.exec_memlimit,
               args.path_to_write_input.string()),
      afl_edge_coverage(args.GetAflCoverageSize()),
      fuzzuf_bb_coverage(args.bb_shm_size),

      // cargv and stdin_mode are initialized at SetCArgvAndDecideInputMode
      last_timeout_ms(args.exec_timelimit_ms),
      record_stdout_and_err(args.record_stdout_and_err),
      filesystem(std::move(args.allowed_path)),
      put_channel()  // TODO: Make channel configurable outside of executor
{
  fuzzuf::utils::CheckCrashHandling();

  SetCArgvAndDecideInputMode();

  // NOTE: The following code should be implemented in
  // Executor::OpenExecutorDependantFiles()
  //      But, currently LinuxForkServerExecutor is not major executor. So we
  //      cannot do that.
  if (stdin_mode) {
    auto path = fuzzuf::utils::StrPrintf(
        "/dev/shm/fuzzuf-cc.forkserver.executor_id-%d.stdin", getpid());
    input_fd =
        fuzzuf::utils::OpenFile(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  } else {
    input_fd = fuzzuf::utils::OpenFile(args.path_to_write_input.string(),
                                       O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  }

  // Allocate shared memory on initialization of Executor
  // It is sufficient if each LinuxForkServerExecutor::Run() can refer the
  // memory
  SetupSharedMemories();
  SetupEnvironmentVariablesForTarget();
  args.AflCoverageSizeToEnvironmentVariables();
  CreateJoinedEnvironmentVariables(std::move(args.environment_variables));

  // Configure PUT runtime settings
  put_channel.SetupForkServer((char *const *)cargv.data(),
                              raw_environment_variables);
  put_channel.SetPUTExecutionTimeout(args.exec_timelimit_ms * 1000);
  if (stdin_mode) {
    put_channel.ReadStdin();
  }
  if (args.record_stdout_and_err) {
    put_channel.SaveStdoutStderr();
  }
}

/**
 * Postcondition:
 *  - Free resources handled by this class, then invalidate data.
 *      - Close input_fd file descriptor. then the value is invalidated
 * (fail-safe)
 *      - If running in fork server mode, close the pipes for communicating with
 * fork server, then terminate fork server process.
 *  - Temporary purpose: If actve_instance which signal handlers refer has a
 * pointer to self value, assign nullptr to it and invalidate.
 */
LinuxForkServerExecutor::~LinuxForkServerExecutor() {
  if (input_fd != -1) {
    fuzzuf::utils::CloseFile(input_fd);
    input_fd = -1;
  }

  if (null_fd != -1) {
    fuzzuf::utils::CloseFile(null_fd);
    null_fd = -1;
  }

  EraseSharedMemories();

  TerminateForkServer();
}

void LinuxForkServerExecutor::SetCArgvAndDecideInputMode() {
  assert(!argv.empty());  // It's incorrect too far

  stdin_mode = true;  // if we find @@, then assign false to stdin_mode

  for (const auto &v : argv) {
    if (v == "@@") {
      stdin_mode = false;
      cargv.emplace_back(path_str_to_write_input.c_str());
    } else {
      cargv.emplace_back(v.c_str());
    }
  }
  cargv.emplace_back(nullptr);
}

void LinuxForkServerExecutor::TerminateForkServer() {
  put_channel.TerminateForkServer();
}

/**
 * Precondition:
 *  - input_fd has a file descriptor that is set by
 * LinuxForkServerExecutor::SetupIO() Postcondition:
 *  - (1) The contents of file refered by input_fd matches to fuzz ( the
 * contents of buf with length of len )
 *  - (2) To execute process that satisfies following requirements ( process
 * that satisfies them is notated as "competent process" ).
 *      - Providing command and commandline arguments specified by constructor
 * argument argv.
 *      - Environment variables satisfy following condition:
 *        * If fuzzuf's basic block coverage is used, receive environment
 * variable __FUZZUF_SHM_ID, then open shared memory which has the specified id.
 *        * If AFL's edge coverage is used, receive environment variable
 * __AFL_SHM_ID, then open shared memory which has the specified id.
 *      - TODO: Specify the requirements of environemnt variables (Items on
 * instrument tool. Currently, only major things are mentioned, as so that can
 * increase for implementing new features. )
 *      - If Executor::stdin_mode is true, use input_fd as a standard input.
 *    (3) Competent process stops execution after the time specified by
 * timeout_ms. As the exception, if the value is 0, the time limit is determined
 * using member variable exec_timelimit_ms. (4) When the method exits, it is
 * triggered by self or third-party signals.
 */
void LinuxForkServerExecutor::Run(const u8 *buf, u32 len, u32 timeout_ms) {
  // locked until std::shared_ptr<u8> lock is used in other places
  while (IsFeedbackLocked()) {
    usleep(100);
  }

  if (timeout_ms == 0) {
    // if timeout_ms is 0, then we use exec_timelimit_ms;
    timeout_ms = exec_timelimit_ms;
  }
  if (timeout_ms != last_timeout_ms) {
    // Update timeout
    put_channel.SetPUTExecutionTimeout(timeout_ms * 1000);
    last_timeout_ms = timeout_ms;
  }

  // Aliases
  ResetSharedMemories();

  WriteTestInputToFile(buf, len);

  //#if 0
  // TODO: Since the information priority is Trace level that is less important
  // than Debug, it should be hidden when runlevel is Debug.
  DEBUG("Run: ");
  DEBUG("%s ", cargv[0]);
  std::for_each(cargv.begin(), cargv.end(),
                [](const char *v) { DEBUG("%s ", v); });
  DEBUG("\n")
  //#endif

  last_exit_reason = feedback::PUTExitReasonType::FAULT_NONE;
  last_signal = 0;

  // FIXME: When persistent mode is implemented, this tmp must be set to the
  // value that represent if the last execution failed for timeout.

  // Request creating PUT process to fork server
  channel::ExecutePUTAPIResponse response = this->put_channel.ExecutePUT();

  // NOTE: Avoids reading shared memory before PUT exit.
  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */
  MEM_BARRIER();

  DEBUG("Response { error=%d, exit_status=%d, signal_number=%d }\n",
        response.error, response.exit_code, response.signal_number);

  if (response.error) {
    last_exit_reason = feedback::PUTExitReasonType::FAULT_ERROR;
    return;
  }

  /* Report outcome to caller. */
  // FIXME: PUT実行がシグナルで止まったときにバグる。
  //  APIのレスポンスが返ったということはPUTが終了したという前提で書いた。
  // TODO: 余裕があったら feedback::PUTExitReasonType
  // に終了コードとシグナル番号を持たせたい
  bool child_timed_out = response.signal_number == SIGKILL;
  if (response.signal_number > 0) {
    last_signal = response.signal_number;

    if (child_timed_out && last_signal == SIGKILL) {
      DEBUG("Reached PUT execution timeout");
      last_exit_reason = feedback::PUTExitReasonType::FAULT_TMOUT;
    } else {
      last_exit_reason = feedback::PUTExitReasonType::FAULT_CRASH;
    }

    return;
  }

  if (uses_asan && response.exit_code == MSAN_ERROR) {
    last_exit_reason = feedback::PUTExitReasonType::FAULT_CRASH;
    return;
  }

  return;
}

void LinuxForkServerExecutor::ReceiveStopSignal(void) {
  // Do nothing
}

u32 LinuxForkServerExecutor::GetAFLMapSize() {
  return afl_edge_coverage.GetMapSize();
}

u32 LinuxForkServerExecutor::GetBBMapSize() {
  return fuzzuf_bb_coverage.GetMapSize();
}

int LinuxForkServerExecutor::GetAFLShmID() {
  return afl_edge_coverage.GetShmID();
}

int LinuxForkServerExecutor::GetBBShmID() {
  return fuzzuf_bb_coverage.GetShmID();
}

feedback::InplaceMemoryFeedback LinuxForkServerExecutor::GetAFLFeedback() {
  return afl_edge_coverage.GetFeedback();
}

feedback::InplaceMemoryFeedback LinuxForkServerExecutor::GetBBFeedback() {
  return fuzzuf_bb_coverage.GetFeedback();
}

feedback::InplaceMemoryFeedback LinuxForkServerExecutor::GetStdOut() {
  if (record_stdout_and_err) {
    std::string path = fuzzuf::utils::StrPrintf(
        "/dev/shm/fuzzuf-cc.forkserver.executor_id-%d.stdout", getpid());
    int fd = fuzzuf::utils::OpenFile(path, O_RDONLY);
    fuzzuf::utils::ReadFileAll(fd, stdout_buffer);
    assert(stdout_buffer.size() > 0);
    fuzzuf::utils::CloseFile(fd);
    // Deleting file `path` might be good
  }
  return feedback::InplaceMemoryFeedback(stdout_buffer.data(),
                                         stdout_buffer.size(), lock);
}

feedback::InplaceMemoryFeedback LinuxForkServerExecutor::GetStdErr() {
  if (record_stdout_and_err) {
    std::string path = fuzzuf::utils::StrPrintf(
        "/dev/shm/fuzzuf-cc.forkserver.executor_id-%d.stderr", getpid());
    int fd = fuzzuf::utils::OpenFile(path, O_RDONLY);
    fuzzuf::utils::ReadFileAll(fd, stderr_buffer);
    fuzzuf::utils::CloseFile(fd);
    // Deleting file `path` might be good
  }
  return feedback::InplaceMemoryFeedback(stderr_buffer.data(),
                                         stderr_buffer.size(), lock);
}

feedback::ExitStatusFeedback LinuxForkServerExecutor::GetExitStatusFeedback() {
  return feedback::ExitStatusFeedback(last_exit_reason, last_signal);
}

bool LinuxForkServerExecutor::IsFeedbackLocked() {
  return (lock.use_count() > 1) || (afl_edge_coverage.GetLockUseCount() > 1) ||
         (fuzzuf_bb_coverage.GetLockUseCount() > 1);
}

// Initialize shared memory group that the PUT writes the coverage.
// These shared memory is reused for all PUTs (It is too slow to allocate for
// each PUT).
void LinuxForkServerExecutor::SetupSharedMemories() {
  afl_edge_coverage.Setup();
  fuzzuf_bb_coverage.Setup();
}

// Since shared memory is reused, it is initialized every time before passed to
// PUT.
void LinuxForkServerExecutor::ResetSharedMemories() {
  afl_edge_coverage.Reset();
  fuzzuf_bb_coverage.Reset();
}

// Delete SharedMemory when the Executor is deleted
void LinuxForkServerExecutor::EraseSharedMemories() {
  afl_edge_coverage.Erase();
  fuzzuf_bb_coverage.Erase();
}

// Since PUT that is instrumented using afl-clang-fast or fuzzuf-cc
// interprets some environment variables, this is the configuration for it.
// Although, this is actually what the child process running PUT should do,
// since there are no environment variables need update for each PUT execution
// for now, by using feature that environment variables are inherited to child
// process, it is enough to do just once ( let's move it if not ). As the
// additional advantage, it can avoid to waste Copy on Write of heap region due
// to StrPrintf.
void LinuxForkServerExecutor::SetupEnvironmentVariablesForTarget() {
  // Pass the id of shared memory to PUT.
  afl_edge_coverage.SetupEnvironmentVariable();
  fuzzuf_bb_coverage.SetupEnvironmentVariable();
  // NOTE: Call extra_feedback.SetupEnvironmentVariable(...) from
  // XXXExecutorInterface

  /* This should improve performance a bit, since it stops the linker from
      doing extra work post-fork(). */
  if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 1);

  // Since MSAN, ASAN and UBSAN related configurations below are inherited from
  // AFL and not used in fuzzuf, it is not required. But since those
  // functionality is  considered implementable without conflicts in fuzzuf in
  // future, these configuration are left.
  setenv("ASAN_OPTIONS",
         "abort_on_error=1:"
         "detect_leaks=0:"
         "malloc_context_size=0:"
         "symbolize=0:"
         "allocator_may_return_null=1:"
         "detect_odr_violation=0:"
         "handle_segv=0:"
         "handle_sigbus=0:"
         "handle_abort=0:"
         "handle_sigfpe=0:"
         "handle_sigill=0",
         0);

  setenv("MSAN_OPTIONS",
         fuzzuf::utils::StrPrintf("exit_code=%d:"
                                  "symbolize=0:"
                                  "abort_on_error=1:"
                                  "malloc_context_size=0:"
                                  "allocator_may_return_null=1:"
                                  "msan_track_origins=0:"
                                  "handle_segv=0:"
                                  "handle_sigbus=0:"
                                  "handle_abort=0:"
                                  "handle_sigfpe=0:"
                                  "handle_sigill=0",
                                  MSAN_ERROR)
             .c_str(),
         0);

  setenv("UBSAN_OPTIONS",
         "halt_on_error=1:"
         "abort_on_error=1:"
         "malloc_context_size=0:"
         "allocator_may_return_null=1:"
         "symbolize=0:"
         "handle_segv=0:"
         "handle_sigbus=0:"
         "handle_abort=0:"
         "handle_sigfpe=0:"
         "handle_sigill=0",
         0);
}

void LinuxForkServerExecutor::CreateJoinedEnvironmentVariables(
    std::vector<std::string> &&extra) {
  environment_variables.clear();
  raw_environment_variables.clear();
  for (auto e = environ; *e; ++e) environment_variables.push_back(*e);
  std::move(extra.begin(), extra.end(),
            std::back_inserter(environment_variables));
  environment_variables.shrink_to_fit();
  raw_environment_variables.reserve(environment_variables.size());
  std::transform(environment_variables.begin(), environment_variables.end(),
                 std::back_inserter(raw_environment_variables),
                 [](const auto &e) { return e.c_str(); });
  raw_environment_variables.push_back(nullptr);
  raw_environment_variables.shrink_to_fit();
}

fuzzuf::executor::output_t LinuxForkServerExecutor::MoveStdOut() {
  GetStdOut();
  return std::move(stdout_buffer);
}

fuzzuf::executor::output_t LinuxForkServerExecutor::MoveStdErr() {
  GetStdErr();
  return std::move(stderr_buffer);
}
}  // namespace fuzzuf::executor
