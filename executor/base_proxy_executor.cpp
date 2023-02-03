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
#include "fuzzuf/executor/base_proxy_executor.hpp"

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
#include "fuzzuf/feedback/file_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/errno_to_system_error.hpp"
#include "fuzzuf/utils/interprocess_shared_object.hpp"
#include "fuzzuf/utils/is_executable.hpp"
#include "fuzzuf/utils/which.hpp"
#include "fuzzuf/utils/workspace.hpp"

namespace fuzzuf::executor {
bool BaseProxyExecutor::has_setup_sighandlers = false;

BaseProxyExecutor *BaseProxyExecutor::active_instance = nullptr;

// Precondition:
//    - A file can be created at path path_str_to_write_input.
//    - If fork server mode, proxy specified by proxy_path behave as fork
//    server.
//    - The derived class constructor is responsible for initializing cargv and
//    stdin_mode.
BaseProxyExecutor::BaseProxyExecutor(const fs::path &proxy_path,
                                     const std::vector<std::string> &pargv,
                                     const std::vector<std::string> &argv,
                                     u32 exec_timelimit_ms, u64 exec_memlimit,
                                     bool forksrv,
                                     const fs::path &path_to_write_input,
                                     bool record_stdout_and_err)
    : Executor(argv, exec_timelimit_ms, exec_memlimit,
               path_to_write_input.string()),
      proxy_path(proxy_path),
      pargv(pargv),
      forksrv(forksrv),

      // cargv and stdin_mode are initialized at SetCArgvAndDecideInputMode
      forksrv_pid(0),
      forksrv_read_fd(-1),
      forksrv_write_fd(-1),
      child_timed_out(false),
      record_stdout_and_err(record_stdout_and_err),
      has_shared_memories(false) {}

// This constructor creates an executor without coverage feedbacks and fork
// server.
BaseProxyExecutor::BaseProxyExecutor(const fs::path &proxy_path,
                                     const std::vector<std::string> &pargv,
                                     const std::vector<std::string> &argv,
                                     u32 exec_timelimit_ms, u64 exec_memlimit,
                                     const fs::path &path_to_write_input)
    : BaseProxyExecutor(proxy_path, pargv, argv, exec_timelimit_ms,
                        exec_memlimit, false, path_to_write_input) {}

// This constructor creates an executor without coverage feedbacks and fork
// server.
BaseProxyExecutor::BaseProxyExecutor(const std::vector<std::string> &argv,
                                     u32 exec_timelimit_ms, u64 exec_memlimit,
                                     const fs::path &path_to_write_input)
    : BaseProxyExecutor("", std::vector<std::string>(), argv, exec_timelimit_ms,
                        exec_memlimit, path_to_write_input) {}

/**
 * Postcondition:
 *     - Run process below in order, with initializing members
 *       * Configure signal handlers (Temporary workaround for non fork server
 * mode. This will be removed in future.)
 *       * Parsing and preprocessing of commandline arguments of PUT.
 *       * Generate a file for sending input to  PUT.
 *       * Configure shared memory
 *         - afl_shm_size should indicate the size of shared memory which PUT
 * built using AFL style cc uses.
 *         - If afl_shm_size sets to zero, it is considered as unused, and never
 * allocate.
 *         - In kernel, Both parameters are round up to multiple of PAGE_SIZE,
 * then memory is allocated.
 *       * Configure environment variables for PUT
 *       * If fork server mode, launch fork server.
 *       * NOTE: Executor does not take care about binding a CPU core. The owner
 * fuzzing algorithm is responsible to it.
 */
void BaseProxyExecutor::Initilize() {
  if (!has_setup_sighandlers) {
    // For the time being, as signal handler is set globally, this function is
    // static method, therefore it is not needed to set again if
    // has_setup_handlers is ture.
    SetupSignalHandlers();
    has_setup_sighandlers = true;
  }

  // Assign self address to static pointer to make signal handlers can refer.
  // active_instance may refer other instance if multiple BaseProxyExecutor
  // exist, therefore following assertion is not appliable.
  // assert(active_instance == nullptr);
  active_instance = this;

  OpenExecutorDependantFiles();

  if (has_shared_memories) {
    // Allocate shared memory on initialization of Executor
    // It is sufficient if each BaseProxyExecutor::Run() can refer the memory
    SetupSharedMemories();
    SetupEnvironmentVariablesForTarget();
  }

  if (forksrv) {
    SetupForkServer();
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

BaseProxyExecutor::~BaseProxyExecutor() {
  // Since active_instance can refer another instance of multiple N, it is
  // considered FuzzerHandle::Reset is called if active_instance is not self
  // value, therefore do nothing. On the other hand, assign nullptr if
  // active_instance is self value. Although, assigning nullptr just in case,
  // since the handlers will never called when the destructor is called, it is
  // basically not a problem.
  if (active_instance == this) {
    active_instance = nullptr;
  }

  if (input_fd != -1) {
    fuzzuf::utils::CloseFile(input_fd);
    input_fd = -1;
  }

  if (null_fd != -1) {
    fuzzuf::utils::CloseFile(null_fd);
    null_fd = -1;
  }

  if (has_shared_memories) {
    EraseSharedMemories();
  }

  if (forksrv) {
    TerminateForkServer();

    // Although, PUT process should be handled by fork server, kill it just in
    // case. (Since fork server is expected to be killed using kill, therefore
    // it will never becoome a zombie. So never wait.)
    KillChildWithoutWait();
  }
}

// Postcondition:
//    - Create command line arguments those are passed to proxy located at
//    proxy_path.
//      * Create cargv in the form of `proxy_path pargv[] -- argv[]`
//    - BaseProxyExecutor executes proxy_path directly, and expects that proxy
//    on proxy_path executes argv[0] in some way.
//      * BaseProxyExecutor doesn't participate on how argv[0] is executed.
//      * proxy_path is expected to behave as fork server in fork server mode.
void BaseProxyExecutor::SetCArgvAndDecideInputMode() {
  assert(!argv.empty());  // It's incorrect too far

  stdin_mode = true;  // if we find @@, then assign false to stdin_mode

  cargv.emplace_back(proxy_path.c_str());

  // Add options which are provided to  proxy application.
  for (const auto &v : pargv) {
    cargv.emplace_back(v.c_str());
  }

  // Commandline options for PUT is appended after "--"
  cargv.emplace_back("--");

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
void BaseProxyExecutor::TerminateForkServer() {
  if (fork_server_epoll_fd != -1) {
    close(fork_server_epoll_fd);
    fork_server_epoll_fd = -1;
  }

  if (forksrv_read_fd != -1) {
    fuzzuf::utils::CloseFile(forksrv_read_fd);
    forksrv_read_fd = -1;
  }

  if (forksrv_write_fd != -1) {
    fuzzuf::utils::CloseFile(forksrv_write_fd);
    forksrv_write_fd = -1;
  }

  if (fork_server_stdout_fd != -1) {
    close(fork_server_stdout_fd);
    fork_server_stdout_fd = -1;
  }

  if (fork_server_stderr_fd != -1) {
    close(fork_server_stderr_fd);
    fork_server_stderr_fd = -1;
  }

  if (forksrv_pid > 0) {
    int status;
    kill(forksrv_pid, SIGKILL);
    waitpid(forksrv_pid, &status, 0);
    forksrv_pid = -1;
  }
}

/**
 * An static method
 * Precondition:
 *  - active_instance has a non-nullptr value definitely when this function is
 * called.
 *  - active_instance has an address of valid Executor instance.
 *  - The global timer exists in the self process, and the function is called
 * for SIGALRM signal. Postcondition:
 *  - The function works as signal handler for SIGALRM
 *      - If called, the PUT is considered as expiring the execution time,
 * therefore kill active_instance->child_pid.
 *      - Set a flag active_instance->child_timed_out
 */
void BaseProxyExecutor::AlarmHandler(int signum) {
  assert(signum == SIGALRM);
  assert(active_instance != nullptr);
  active_instance->KillChildWithoutWait();
  active_instance->child_timed_out = true;
}

/*
 * An static method
 * Postcondition:
 *  - It defines how the fuzzuf process respond to signals.
 *  - If signal handlers are needed, signal handlers are set.
 * FIXME: Since the configuration on signal handlers is shared in whole process,
 * it affects all fuzzuf instances running on the process.
 * As the result, it requires change of process design in some cases,
 * Therefore, the process design may be changed,
 * yet currently the static function is implemented under the expection that
 * only one fuzzuf instance is used simultaneously.
 */
void BaseProxyExecutor::SetupSignalHandlers() {
  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

// Since there is no agreement on handling following signals, ignoring for now.
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

  sa.sa_handler = BaseProxyExecutor::AlarmHandler;
  sigaction(SIGALRM, &sa, NULL);
}

namespace detail {
template <typename Dest>
bool read_chunk(Dest &dest, int fd) {
  std::size_t cur_size = dest.size();
  dest.resize(cur_size + fuzzuf::executor::output_block_size);
  auto read_stat = read(fd, std::next(dest.data(), cur_size),
                        fuzzuf::executor::output_block_size);
  if (read_stat < 0) {
    dest.resize(cur_size);  // reset dest, whatever the error is

    int e = errno;
    if (e == EAGAIN || e == EWOULDBLOCK)
      return false;
    else if (!(e == EINTR))
      throw fuzzuf::utils::errno_to_system_error(
          e, "read from child process failed during the execution");
  } else
    dest.resize(cur_size + read_stat);
  return read_stat != 0;
}
}  // namespace detail

/**
 * Precondition:
 *  - input_fd has a file descriptor that is set by BaseProxyExecutor::SetupIO()
 * Postcondition:
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
 * triggered by self or third-party signals. (5) Assign process ID of competent
 * process to child_pid
 *      - This postcondition is needed for third-party to exit competent process
 *        Is there need for third-party to exit the process in future? -> It
 * might be used in the case signal handler is in use. The postcondition is left
 * for future extension.
 */
void BaseProxyExecutor::Run(const u8 *buf, u32 len, u32 timeout_ms) {
  // locked until std::shared_ptr<u8> lock is used in other places
  while (IsFeedbackLocked()) {
    usleep(100);
  }

  // if timeout_ms is 0, then we use exec_timelimit_ms;
  if (timeout_ms == 0) timeout_ms = exec_timelimit_ms;

  // Aliases
  ResetSharedMemories();
  if (record_stdout_and_err) {
    stdout_buffer.clear();
    stderr_buffer.clear();
  }

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

  // This structure is shared by both parent process and child process.
  // Since execv never returns on success, it is initialized as success(0), then
  // set value on failed.
  auto child_state = fuzzuf::utils::interprocess::create_shared_object(
      fuzzuf::executor::ChildState{0, 0});

  std::array<int, 2u> stdout_fd{0, 0};
  std::array<int, 2u> stderr_fd{0, 0};
  constexpr std::size_t read_size = 8u;
  boost::container::static_vector<std::uint8_t, read_size> read_buffer;
  bool timeout = true;
  if (forksrv) {
    // The value tmp which is needed only on persistent mode that is currently
    // not implemented.
    static u8 tmp[4];

    // Request creating PUT process to fork server
    // The  new PUT execution can be requested to the fork server by writing 4
    // byte of values to the pipe. If the PUT launched successfully, the pid of
    // PUT process is returned via the pipe. WriteFile, ReadFile throw exception
    // if writing or reading couldn't consume specified bytes.
    try {
      // FIXME: When persistent mode is implemented, this tmp must be set to the
      // value that represent if the last execution failed for timeout.
      fuzzuf::utils::WriteFile(forksrv_write_fd, tmp, 4);

      read_buffer.resize(4u);
      fuzzuf::utils::ReadFile(forksrv_read_fd, read_buffer.data(), 4u, false);

      epoll_event event;
      auto left_ms = timeout_ms;
      while (left_ms > 0) {
        const auto begin_date = std::chrono::steady_clock::now();
        auto event_count = epoll_wait(fork_server_epoll_fd, &event, 1, left_ms);
        if (event_count < 0) {
          int e = errno;
          if (e != EINTR)
            throw fuzzuf::utils::errno_to_system_error(
                e, "epoll_wait failed during the execution");
        } else if (event_count == 0)
          break;
        else {
          if (event.events & EPOLLIN) {
            if (event.data.fd == fork_server_stdout_fd)
              // Although the buffer may contain data larger than
              // output_block_size, that is not a problem as it is level
              // trigger.
              detail::read_chunk(stdout_buffer, fork_server_stdout_fd);
            else if (event.data.fd == fork_server_stderr_fd)
              // Although the buffer may contain data larger than
              // output_block_size, that is not a problem as it is level
              // trigger.
              detail::read_chunk(stderr_buffer, fork_server_stderr_fd);
            else if (event.data.fd == forksrv_read_fd) {
              std::size_t cur_size = read_buffer.size();
              read_buffer.resize(read_size);
              auto read_stat =
                  read(forksrv_read_fd, std::next(read_buffer.data(), cur_size),
                       read_size - cur_size);
              if (read_stat < 0) {
                int e = errno;
                if (!(e == EAGAIN || e == EINTR || e == EWOULDBLOCK))
                  throw fuzzuf::utils::errno_to_system_error(
                      e,
                      "read pid from child process failed during the "
                      "execution");
              } else {
                read_buffer.resize(cur_size + read_stat);
                if (read_buffer.size() == read_size) {
                  left_ms = 0;
                  timeout = false;
                }
              }
            }
          }
          if (event.events == EPOLLHUP || event.events == EPOLLERR)
            ERROR("pipe to the child process was unexpectedly closed");
        }
        const auto end_date = std::chrono::steady_clock::now();
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_date -
                                                                  begin_date)
                .count();
        if (left_ms < elapsed)
          left_ms = 0;
        else
          left_ms -= elapsed;
      }
    } catch (const utils::FileError &e) {
      ERROR("Unable to request new process from fork server (OOM?)");
    }
    if (read_buffer.size() >= 4u)
      child_pid = *reinterpret_cast<std::uint32_t *>(read_buffer.data());

    if (child_pid <= 0) ERROR("Fork server is misbehaving (OOM?)");
  } else {
    if (record_stdout_and_err) {
      if (pipe(stdout_fd.data()) < 0) {
        throw fuzzuf::utils::errno_to_system_error(
            errno, "Unable to create stdout pipe");
      }
      if (pipe(stderr_fd.data()) < 0) {
        throw fuzzuf::utils::errno_to_system_error(
            errno, "Unable to create stderr pipe");
      }
    }

    child_pid = fuzzuf::utils::Fork();
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

      if (record_stdout_and_err) {
        dup2(stdout_fd[1], 1);
        dup2(stderr_fd[1], 2);
        close(stdout_fd[0]);
        close(stdout_fd[1]);
        close(stderr_fd[0]);
        close(stderr_fd[1]);
      } else {
        dup2(null_fd, 1);
        dup2(null_fd, 2);
      }

      if (stdin_mode) {
        dup2(input_fd, 0);
      } else {
        // stdin is bound to /dev/null ( Providing "nothing" as input ).
        dup2(null_fd, 0);
      }

      // Execute new executable binary on the child process.
      // If failed, that matter is recorded to child_state.
      child_state->exec_result = execv(cargv[0], (char **)cargv.data());
      child_state->exec_errno = errno;

      /* Use a distinctive bitmap value to tell the parent about execv()
          falling through. */

      exit(0);
    }
  }

  int put_status;  // PUT's status(retrieved via waitpid)
  if (forksrv) {
    if (timeout) {  // The execution time may exceeded due to input that causes
                    // hanging was passed.
      KillChildWithoutWait();  // After killing PUT that timed out, retrive
                               // put_status from fork server again.
      child_timed_out = true;
    }

    if (read_buffer.size() < 8u) {
      std::size_t cur_size = read_buffer.size();
      read_buffer.resize(read_size);
      fuzzuf::utils::ReadFile(forksrv_read_fd,
                              std::next(read_buffer.data(), cur_size),
                              read_size - cur_size, false);
    }

    if (record_stdout_and_err) {
      while (detail::read_chunk(stdout_buffer, fork_server_stdout_fd))
        ;
      while (detail::read_chunk(stderr_buffer, fork_server_stderr_fd))
        ;
    }

    if (read_buffer.size() >= 8u)
      put_status =
          *reinterpret_cast<std::uint32_t *>(std::next(read_buffer.data(), 4u));
    else
      ERROR("Unable to communicate with fork server (OOM?)");
  } else {
    // Initialize a flag that indicate whether the PUT hanged.
    // It is set in the signal handler.
    child_timed_out = false;

    static struct itimerval it;

    // Set timer to make SIGALRM to be sent on timeout.
    // The handler for SIGALRM is set to BaseProxyExecutor::AlarmHandler, and
    // the PUT is killed in inside. Yet SIGALRM is not set if exec_timelimit_ms
    // is set to 0.
    if (exec_timelimit_ms) {
      it.it_value.tv_sec = (timeout_ms / 1000);
      it.it_value.tv_usec = (timeout_ms % 1000) * 1000;
      setitimer(ITIMER_REAL, &it, NULL);
    }

    // If record_stdout_and_err is true, here starts the loop for saving outputs
    // to buffers.
    if (record_stdout_and_err) {
      close(stdout_fd[1]);
      close(stderr_fd[1]);

      auto epoll_fd = epoll_create(1);
      epoll_event stdout_event;
      stdout_event.data.fd = stdout_fd[0];
      stdout_event.events = EPOLLIN | EPOLLRDHUP;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stdout_fd[0], &stdout_event) < 0) {
        throw fuzzuf::utils::errno_to_system_error(
            errno, "Unable to epoll stdout pipe");
      }

      epoll_event stderr_event;
      stderr_event.data.fd = stderr_fd[0];
      stderr_event.events = EPOLLIN | EPOLLRDHUP;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stderr_fd[0], &stderr_event) < 0) {
        throw fuzzuf::utils::errno_to_system_error(
            errno, "Unable to epoll stdout pipe");
      }

      epoll_event event;
      auto left_ms = timeout_ms;
      unsigned int closed_count = 0u;
      fcntl(stdout_fd[0], F_SETFL, O_NONBLOCK);
      fcntl(stderr_fd[0], F_SETFL, O_NONBLOCK);
      while (left_ms > 0) {
        const auto begin_date = std::chrono::steady_clock::now();
        auto event_count = epoll_wait(epoll_fd, &event, 1, left_ms);
        if (event_count < 0) {
          int e = errno;
          if (e != EINTR) {
            throw fuzzuf::utils::errno_to_system_error(
                e, "epoll_wait failed during the execution");
          }
        } else if (event_count == 0)
          break;
        else {
          if (event.events & EPOLLIN) {
            if (event.data.fd == stdout_fd[0])
              // Although the buffer may contain data larger than
              // output_block_size, that is not a problem as it is level
              // trigger.
              detail::read_chunk(stdout_buffer, stdout_fd[0]);
            else if (event.data.fd == stderr_fd[0])
              // Although the buffer may contain data larger than
              // output_block_size, that is not a problem as it is level
              // trigger.
              detail::read_chunk(stderr_buffer, stderr_fd[0]);
          }
          if (event.events == EPOLLHUP || event.events == EPOLLERR) {
            ++closed_count;
            if (closed_count == 2u) break;
          }
        }
        const auto end_date = std::chrono::steady_clock::now();
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_date -
                                                                  begin_date)
                .count();
        if (left_ms < elapsed)
          left_ms = 0;
        else
          left_ms -= elapsed;
      }
      close(epoll_fd);
    }

    if (waitpid(child_pid, &put_status, 0) <= 0) ERROR("waitpid() failed");

    if (record_stdout_and_err) {
      {
        bool cont = true;
        while (cont) {
          cont = detail::read_chunk(stdout_buffer, stdout_fd[0]);
        }
      }
      {
        bool cont = true;
        while (cont) {
          cont = detail::read_chunk(stderr_buffer, stderr_fd[0]);
        }
      }
      close(stdout_fd[0]);
      close(stderr_fd[0]);
    }

    // Reset the timer.
    if (exec_timelimit_ms) {
      it.it_value.tv_sec = 0;
      it.it_value.tv_usec = 0;
      setitimer(ITIMER_REAL, &it, NULL);
    }
  }

  // If the PUT process is not stopped but exited ( It should happen except in
  // persistent mode ), since child_pid is no longer needed, it can be set to 0.
  if (!WIFSTOPPED(put_status)) child_pid = 0;
  DEBUG("Exec Status %d (pid %d)\n", put_status, child_pid);

  /* Any subsequent operations on trace_bits must not be moved by the
      compiler below this point. Past this location, trace_bits[] behave
      very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  // Following implementation is dirty.
  // This may be inherited implementation from afl, and it may feel dirty, so it
  // shall be fixed.

  u32 tb4 = 0;

  // Consider execution was failed if execv of child process failed.
  if (child_state->exec_result < 0) tb4 = EXEC_FAIL_SIG;

  last_exit_reason = feedback::PUTExitReasonType::FAULT_NONE;
  last_signal = 0;

  /* Report outcome to caller. */
  if (WIFSIGNALED(put_status)) {
    last_signal = WTERMSIG(put_status);

    if (child_timed_out && last_signal == SIGKILL)
      last_exit_reason = feedback::PUTExitReasonType::FAULT_TMOUT;
    else
      last_exit_reason = feedback::PUTExitReasonType::FAULT_CRASH;

    return;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
  must use a special exit code. */

  if (uses_asan && WEXITSTATUS(put_status) == MSAN_ERROR) {
    last_exit_reason = feedback::PUTExitReasonType::FAULT_CRASH;
    return;
  }

  if (!forksrv && tb4 == EXEC_FAIL_SIG) {
    last_exit_reason = feedback::PUTExitReasonType::FAULT_ERROR;
    return;
  }

  last_exit_reason = feedback::PUTExitReasonType::FAULT_NONE;
  return;
}

feedback::InplaceMemoryFeedback BaseProxyExecutor::GetStdOut() {
  return feedback::InplaceMemoryFeedback(stdout_buffer.data(),
                                         stdout_buffer.size(), lock);
}

feedback::InplaceMemoryFeedback BaseProxyExecutor::GetStdErr() {
  return feedback::InplaceMemoryFeedback(stderr_buffer.data(),
                                         stderr_buffer.size(), lock);
}

feedback::FileFeedback BaseProxyExecutor::GetFileFeedback(fs::path feed_path) {
  return feedback::FileFeedback(feed_path, lock);
}

feedback::ExitStatusFeedback BaseProxyExecutor::GetExitStatusFeedback() {
  return feedback::ExitStatusFeedback(last_exit_reason, last_signal);
}

bool BaseProxyExecutor::IsFeedbackLocked() { return (lock.use_count() > 1); }

// Initialize shared memory group that the PUT writes the coverage.
// These shared memory is reused for all PUTs (It is too slow to allocate for
// each PUT).
void BaseProxyExecutor::SetupSharedMemories() {}

// Since shared memory is reused, it is initialized every time before passed to
// PUT.
void BaseProxyExecutor::ResetSharedMemories() {}

// Delete SharedMemory when the Executor is deleted
void BaseProxyExecutor::EraseSharedMemories() {}

// Since PUT that is instrumented using afl-clang-fast or fuzzuf-cc
// interprets some environment variables, this is the configuration for it.
// Although, this is actually what the child process running PUT should do,
// since there are no environment variables need update for each PUT execution
// for now, by using feature that environment variables are inherited to child
// process, it is enough to do just once ( let's move it if not ). As the
// additional advantage, it can avoid to waste Copy on Write of heap region due
// to StrPrintf.
void BaseProxyExecutor::SetupEnvironmentVariablesForTarget() {
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

/*
 * Precondition:
 *  - The target PUT is a binary that supports fork server mode.
 * Postcondition:
 *  - Generate child process, then launch PUT in fork server mode on the child
 * process side.
 *  - Apply proper limits ( ex. memory limits ) on PUT.
 *  - Setup the pipe between parent process ( the process that runs fuzzuf ) and
 * child process.
 */
void BaseProxyExecutor::SetupForkServer() {
  // set of fd of pipe.
  // Each is used for parent -> child and child -> parent data transfer.
  int par2chld[2], chld2par[2];

  if (pipe(par2chld) || pipe(chld2par)) ERROR("pipe() failed");

  std::array<int, 2u> stdout_fd{-1, -1};
  std::array<int, 2u> stderr_fd{-1, -1};

  if (record_stdout_and_err) {
    if (pipe(stdout_fd.data()) < 0) {
      ERROR("Unable to create stdout pipe");
    }
    if (pipe(stderr_fd.data()) < 0) {
      ERROR("Unable to create stderr pipe");
    }
  }

  forksrv_pid = fork();
  if (forksrv_pid < 0) ERROR("fork() failed");

  if (!forksrv_pid) {
    struct rlimit r;
    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    // Although since FORKSRV_FD_WRITE=199, FORKSRV_FD_READ=198, the required
    // limit is 200, set std::max() + 1 to suppose those values are changed in
    // future.
    long unsigned int needed_fd_lim =
        std::max(FORKSRV_FD_WRITE, FORKSRV_FD_READ) + 1;
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < needed_fd_lim) {
      r.rlim_cur = needed_fd_lim;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    if (exec_memlimit) {
      r.rlim_max = r.rlim_cur = ((rlim_t)exec_memlimit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */
      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
#endif /* ^RLIMIT_AS */
    }

    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r);

    setsid();

    if (record_stdout_and_err) {
      dup2(stdout_fd[1], 1);
      dup2(stderr_fd[1], 2);
      close(stdout_fd[0]);
      close(stderr_fd[0]);
    } else {
      dup2(null_fd, 1);
      dup2(null_fd, 2);
    }

    if (stdin_mode) {
      dup2(input_fd, 0);
    } else {
      dup2(null_fd, 0);
    }

    if (dup2(par2chld[0], FORKSRV_FD_READ) < 0) ERROR("dup2() failed");
    if (dup2(chld2par[1], FORKSRV_FD_WRITE) < 0) ERROR("dup2() failed");

    close(par2chld[0]);
    close(par2chld[1]);
    close(chld2par[0]);
    close(chld2par[1]);

    execve(cargv[0], (char **)cargv.data(), environ);
    // TODO: It must be discussed whether it is needed that equivalent to
    // EXEC_FAIL_SIG that is used in non-fork server mode.
    exit(0);
  }

  DEBUG("cargv[0]: %s", cargv[0]);
  close(par2chld[0]);
  close(chld2par[1]);

  if (record_stdout_and_err) {
    close(stdout_fd[1]);
    close(stderr_fd[1]);
    fork_server_stdout_fd = stdout_fd[0];
    fork_server_stderr_fd = stderr_fd[0];
    fcntl(fork_server_stdout_fd, F_SETFL, O_NONBLOCK);
    fcntl(fork_server_stderr_fd, F_SETFL, O_NONBLOCK);
  }

  fork_server_epoll_fd = epoll_create(1);

  if (record_stdout_and_err) {
    fork_server_stdout_event.data.fd = fork_server_stdout_fd;
    fork_server_stdout_event.events = EPOLLIN | EPOLLRDHUP;
    if (epoll_ctl(fork_server_epoll_fd, EPOLL_CTL_ADD, fork_server_stdout_fd,
                  &fork_server_stdout_event) < 0) {
      ERROR("Unable to epoll stdout pipe");
    }

    fork_server_stderr_event.data.fd = fork_server_stderr_fd;
    fork_server_stderr_event.events = EPOLLIN | EPOLLRDHUP;
    if (epoll_ctl(fork_server_epoll_fd, EPOLL_CTL_ADD, fork_server_stderr_fd,
                  &fork_server_stderr_event) < 0) {
      ERROR("Unable to epoll stderr pipe");
    }
  }

  forksrv_write_fd = par2chld[1];
  forksrv_read_fd = chld2par[0];
  fork_server_read_event.data.fd = forksrv_read_fd;
  fork_server_read_event.events = EPOLLIN | EPOLLRDHUP;
  if (epoll_ctl(fork_server_epoll_fd, EPOLL_CTL_ADD, forksrv_read_fd,
                &fork_server_read_event) < 0) {
    ERROR("Unable to epoll read pipe");
  }

  // Wait for fork server to launch with 10 seconds of time limit (Conforming
  // AFL++ that looks waiting 10 seconds.). The handshake is sent from remote on
  // launched.
  u8 tmp[4];
  u32 time_limit = 10000;
  u32 time_ms =
      fuzzuf::utils::ReadFileTimed(forksrv_read_fd, &tmp, 4, time_limit);
  if (time_ms == 0) {
    // Error during reading
    TerminateForkServer();
    MSG("\n" cLRD "[-] " cRST
        "Hmm, looks like the target binary terminated before we could complete "
        "a\n"
        "handshake with the injected code. You can try the following:\n\n"
        "    - Possibly the target is not a valid executable. Check:\n"
        "      - The target exists and a valid ELF binary.\n"
        "      - The target is instrumented.\n"
        "        Retry with fork server disabled.\n");
    ABORT("Fork server handshake failed");
  } else if (time_ms > time_limit) {
    // Timeout
    TerminateForkServer();
    ABORT("Timeout while initializing fork server (Default time limit is 10s)");
  }

  return;
}

// this function may be called in signal handlers.
// use only async-signal-safe functions inside.
// basically, we care about only the case where BaseProxyExecutor::Run is
// running. in that case, we should kill the child process(of PUT) so that
// BaseProxyExecutor could halt without waiting the timeout. if this function is
// called during the call of other functions, then the child process is not
// active. we can call KillChildWithoutWait() anyways because the function
// checks if the child process is active.
void BaseProxyExecutor::ReceiveStopSignal(void) {
  // kill is async-signal-safe
  // the child process is active only in BaseProxyExecutor::Run and Run always
  // uses waitpid, so we don't need to use waitpid here
  KillChildWithoutWait();
}

fuzzuf::executor::output_t BaseProxyExecutor::MoveStdOut() {
  return std::move(stdout_buffer);
}

fuzzuf::executor::output_t BaseProxyExecutor::MoveStdErr() {
  return std::move(stderr_buffer);
}
}  // namespace fuzzuf::executor
