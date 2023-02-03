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
#pragma once

#include <sys/epoll.h>

#include <cassert>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "fuzzuf/coverage/afl_edge_cov_attacher.hpp"
#include "fuzzuf/coverage/fuzzuf_bb_cov_attacher.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/vfs/local_filesystem.hpp"

namespace fuzzuf::executor {
// A class for fuzz execution under native Linux environment (i.e. the Linux
// environment where the fuzzer tracer and the fuzz target are the same)
//
// Responsibility:
//  - Class member Executor::argv must hold the information required for an
//  execution of the fuzzing target process (e.g. command, arguments)
//
// Responsibility (TODO):
//  - The lifetime for the class itself and the time period of validity of
//  member variables must match (TODO because checks have not completed)
//      - This is to ensure the robustness
class NativeLinuxExecutor : public Executor {
 public:
  static constexpr u32 EXEC_FAIL_SIG = 0xfee1dead;
  /* Distinctive exit code used to indicate MSAN trip condition: */
  static constexpr u32 MSAN_ERROR = 86;

  static constexpr int FORKSRV_FD_READ = 198;
  static constexpr int FORKSRV_FD_WRITE = 199;

  // Members holding settings handed over a constructor
  const bool forksrv;

  const bool uses_asan = false;  // May become one of the available options in
                                 // the future, but currently not anticipated

  coverage::AFLEdgeCovAttacher afl_edge_coverage;
  coverage::FuzzufBBCovAttacher fuzzuf_bb_coverage;

  int forksrv_pid;
  int forksrv_read_fd;
  int forksrv_write_fd;

  bool child_timed_out;

  static bool has_setup_sighandlers;
  // A pointer to a currently active instance, used by a signal handler.
  // nullptr if no such instance.
  // Beware that it temporarily assumes that multiple fuzzer instances do not
  // become active simultaneously.
  static NativeLinuxExecutor *active_instance;

  NativeLinuxExecutor(
      const std::vector<std::string> &argv, u32 exec_timelimit_ms,
      u64 exec_memlimit, bool forksrv, const fs::path &path_to_write_input,
      u32 afl_shm_size, u32 bb_shm_size,
      // FIXME: The below is a temporary flag to avoid a big performance issue.
      // The issue appears when we save the outputs of stdout/stderr to buffers
      // in every execution of a PUT, which isn't required in most fuzzers.
      // This is just a temporary and ugly countermeasure.
      // In the future, we should generalize this flag so that we can
      // arbitrarily specify which fd should be recorded. For example, by
      // passing std::vector<int>{1, 2} to this class, we would tell that we
      // would like to record stdout and stderr.
      bool record_stdout_and_err = false,
      std::vector<std::string> &&environment_variables_ = {},
      std::vector<fs::path> &&allowed_path_ = {});
  ~NativeLinuxExecutor();

  NativeLinuxExecutor(const NativeLinuxExecutor &) = delete;
  NativeLinuxExecutor(NativeLinuxExecutor &&) = delete;
  NativeLinuxExecutor &operator=(const NativeLinuxExecutor &) = delete;
  NativeLinuxExecutor &operator=(NativeLinuxExecutor &&) = delete;
  NativeLinuxExecutor() = delete;

  // Common methods among children on Executor classes
  // Declare in the base class and define in each derivative, if possible (how
  // to achieve?)
  void Run(const u8 *buf, u32 len, u32 timeout_ms = 0);
  void ReceiveStopSignal(void);

  // Environment-specific methods
  u32 GetAFLMapSize();
  u32 GetBBMapSize();
  int GetAFLShmID();
  int GetBBShmID();

  feedback::InplaceMemoryFeedback GetAFLFeedback();
  feedback::InplaceMemoryFeedback GetBBFeedback();
  feedback::InplaceMemoryFeedback GetStdOut();
  feedback::InplaceMemoryFeedback GetStdErr();
  feedback::ExitStatusFeedback GetExitStatusFeedback();

  virtual bool IsFeedbackLocked();

  void TerminateForkServer();
  void SetCArgvAndDecideInputMode();
  void SetupSharedMemories();
  void ResetSharedMemories();
  void EraseSharedMemories();
  void SetupEnvironmentVariablesForTarget();
  void SetupForkServer();

  static void SetupSignalHandlers();
  static void AlarmHandler(int signum);

  // InplaceMemoryFeedback made of GetStdOut before calling this function
  // becomes invalid after Run()
  fuzzuf::executor::output_t MoveStdOut();
  // InplaceMemoryFeedback made of GetStdErr before calling this function
  // becomes invalid after Run()
  fuzzuf::executor::output_t MoveStdErr();

  fuzzuf::utils::vfs::LocalFilesystem &Filesystem() { return filesystem; }

 private:
  /**
   * Take snapshot of environment variables.
   * This updates both environment_variables and raw_environment_variables.
   * @param extra Executor specific environment variables those are set only on
   * the child process of this executor.
   */
  void CreateJoinedEnvironmentVariables(std::vector<std::string> &&extra);
  feedback::PUTExitReasonType last_exit_reason;
  u8 last_signal;
  fuzzuf::executor::output_t stdout_buffer;
  fuzzuf::executor::output_t stderr_buffer;
  int fork_server_stdout_fd = -1;
  int fork_server_stderr_fd = -1;
  int fork_server_epoll_fd = -1;
  epoll_event fork_server_stdout_event;
  epoll_event fork_server_stderr_event;
  epoll_event fork_server_read_event;

  bool record_stdout_and_err;

  /**
   * Snapshot of environment variables.
   * This contains following values.
   * * All global environment variables available whien the constructor is
   * executed.
   * * Executor specific environment variables specified on the constructor
   * argument. The child process invoked by this executor will take these values
   * as environment variables. (This means the executor created prior to
   * modification of environment variables will take old environment variables)
   */
  std::vector<std::string> environment_variables;

  /**
   * Since some C APIs require environment variables in null terminated array of
   * C-string, environment_variables is transformed into that form. Each element
   * of raw_environment_variables points value of environment_variables except
   * last value that points nullptr. raw_environment_variables should be rebuilt
   * if environment_variables is modified.
   */
  std::vector<const char *> raw_environment_variables;
  fuzzuf::utils::vfs::LocalFilesystem filesystem;
};

}  // namespace fuzzuf::executor
