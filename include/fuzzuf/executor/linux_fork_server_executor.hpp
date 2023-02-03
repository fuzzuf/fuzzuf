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

#include "fuzzuf/channel/fd_channel.hpp"
#include "fuzzuf/coverage/afl_edge_cov_attacher.hpp"
#include "fuzzuf/coverage/fuzzuf_bb_cov_attacher.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/get_aligned_addr.hpp"
#include "fuzzuf/utils/setter.hpp"
#include "fuzzuf/utils/vfs/local_filesystem.hpp"

namespace fuzzuf::executor {
/**
 * @brief Parameters required to create LinuxForkServerExecutor
 */
struct LinuxForkServerExecutorParameters {
  FUZZUF_MOVABLE
  FUZZUF_SETTER(argv)
  FUZZUF_SETTER(exec_timelimit_ms)
  FUZZUF_SETTER(exec_memlimit)
  FUZZUF_SETTER(path_to_write_input)
  FUZZUF_SETTER(afl_shm_size)
  FUZZUF_SETTER(bb_shm_size)
  FUZZUF_SETTER(ijon_counter_shm_size)
  FUZZUF_SETTER(ijon_max_shm_size)
  FUZZUF_SETTER(record_stdout_and_err)
  FUZZUF_SETTER(environment_variables)
  FUZZUF_SETTER(allowed_path)
  /*
   * Calculate offset for IJON Counter
   */
  u32 GetIjonCounterOffset() const {
    return fuzzuf::utils::get_aligned_addr(afl_shm_size,
                                           alignof(std::uint64_t));
  }
  /*
   * Calculate offset for IJON Max
   */
  u32 GetIjonMaxOffset() const {
    return fuzzuf::utils::get_aligned_addr(
        GetIjonCounterOffset() + ijon_counter_shm_size, alignof(std::uint64_t));
  }
  /*
   * Calculate total required shared memory size.
   * Note that this is not AFL coverage size in IJON, but sum of all required
   * buffer size. During such extra buffers are not in use, the value is equal
   * to AFL coverage size.
   */
  u32 GetAflCoverageSize() const {
    return fuzzuf::utils::get_aligned_addr(
        GetIjonMaxOffset() + ijon_max_shm_size, alignof(std::uint64_t));
  }
  /**
   * Convert afl_coverage_size to environment variable string.
   * If IJON related values are specified, those values are serialized too.
   * Since the function just add environment variables above and never erase
   * existing one, the function should called just once.
   * @returns *this in reference
   */
  LinuxForkServerExecutorParameters &AflCoverageSizeToEnvironmentVariables() {
    std::string afl_coverage_size_str("__AFL_SIZE=");
    afl_coverage_size_str += std::to_string(GetIjonCounterOffset());
    environment_variables.emplace_back(std::move(afl_coverage_size_str));
    if (ijon_counter_shm_size) {
      std::string ijon_counter_size_str("__IJON_COUNTER_SIZE=");
      ijon_counter_size_str +=
          std::to_string(GetIjonMaxOffset() - GetIjonCounterOffset());
      environment_variables.emplace_back(std::move(ijon_counter_size_str));
    }
    if (ijon_max_shm_size) {
      std::string ijon_max_size_str("__IJON_MAX_SIZE=");
      ijon_max_size_str +=
          std::to_string(GetAflCoverageSize() - GetIjonMaxOffset());
      environment_variables.emplace_back(std::move(ijon_max_size_str));
    }
    return *this;
  }
  std::vector<std::string> argv;
  u32 exec_timelimit_ms = 0u;
  u64 exec_memlimit = 0u;
  fs::path path_to_write_input = "input";
  u32 afl_shm_size = 0u;
  u32 bb_shm_size = 0u;
  u32 ijon_counter_shm_size = 0u;
  u32 ijon_max_shm_size = 0u;
  // FIXME: The below is a temporary flag to avoid a big performance issue.
  // The issue appears when we save the outputs of stdout/stderr to buffers
  // in every execution of a PUT, which isn't required in most fuzzers.
  // This is just a temporary and ugly countermeasure.
  // In the future, we should generalize this flag so that we can arbitrarily
  // specify which fd should be recorded. For example, by passing
  // std::vector<int>{1, 2} to this class, we would tell that we would like to
  // record stdout and stderr.
  bool record_stdout_and_err = false;
  std::vector<std::string> environment_variables;
  std::vector<fs::path> allowed_path;
};

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
class LinuxForkServerExecutor : public Executor {
 public:
  static constexpr u32 EXEC_FAIL_SIG = 0xfee1dead;
  /* Distinctive exit code used to indicate MSAN trip condition: */
  static constexpr u32 MSAN_ERROR = 86;

  const bool uses_asan = false;  // May become one of the available options in
                                 // the future, but currently not anticipated

  coverage::AFLEdgeCovAttacher afl_edge_coverage;
  coverage::FuzzufBBCovAttacher fuzzuf_bb_coverage;

  LinuxForkServerExecutor(LinuxForkServerExecutorParameters &&args);
  ~LinuxForkServerExecutor();

  LinuxForkServerExecutor(const LinuxForkServerExecutor &) = delete;
  LinuxForkServerExecutor(LinuxForkServerExecutor &&) = delete;
  LinuxForkServerExecutor &operator=(const LinuxForkServerExecutor &) = delete;
  LinuxForkServerExecutor &operator=(LinuxForkServerExecutor &&) = delete;
  LinuxForkServerExecutor() = delete;

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

  u32 last_timeout_ms;
  feedback::PUTExitReasonType last_exit_reason;
  u8 last_signal;
  fuzzuf::executor::output_t stdout_buffer;
  fuzzuf::executor::output_t stderr_buffer;

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

  channel::FdChannel put_channel;
};
}  // namespace fuzzuf::executor
