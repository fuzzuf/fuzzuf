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

/**
 * @file shm_cov_attacher.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_COVERAGE_SHM_COV_ATTACHER_HPP
#define FUZZUF_INCLUDE_COVERAGE_SHM_COV_ATTACHER_HPP

#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::coverage {

/**
 * @class ShmCovAttacher
 * @brief Base class that attaches coverage stored in shared memory.
 */
class ShmCovAttacher {
 public:
  static constexpr int INVALID_SHMID = -1;

  u8 *trace_bits;

  ShmCovAttacher(u32 map_size)
      : trace_bits(nullptr), map_size(map_size), shmid(INVALID_SHMID) {}

  ~ShmCovAttacher() { Erase(); }

  ShmCovAttacher(const ShmCovAttacher &) = delete;
  ShmCovAttacher(ShmCovAttacher &&) = delete;
  ShmCovAttacher &operator=(const ShmCovAttacher &) = delete;
  ShmCovAttacher &operator=(ShmCovAttacher &&) = delete;
  ShmCovAttacher() = delete;

  void Setup(void) {
    if (map_size == 0) return;
    shmid = shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | 0600);
    if (shmid < 0) ERROR("shmget() failed");

    trace_bits = (u8 *)shmat(shmid, nullptr, 0);
    if (trace_bits == (u8 *)-1) ERROR("shmat() failed");
  }

  void Reset(void) {
    if (map_size == 0) return;
    if (trace_bits != nullptr) {
      std::memset(trace_bits, 0, map_size);
    }

    MEM_BARRIER();
  }

  void Erase(void) {
    if (map_size == 0) return;
    if (trace_bits != nullptr) {
      if (shmdt(trace_bits) == -1) ERROR("shmdt() failed");
      trace_bits = nullptr;
    }
    if (shmid != INVALID_SHMID) {
      if (shmctl(shmid, IPC_RMID, 0) == -1) ERROR("shmctl() failed");
      shmid = INVALID_SHMID;
    }
  }

  void SetupEnvironmentVariable(const char *shm_env_var) {
    if (map_size > 0 && shmid != INVALID_SHMID) {
      std::string shmstr = std::to_string(shmid);
      setenv(shm_env_var, shmstr.c_str(), 1);
    } else {
      unsetenv(shm_env_var);
    }
  }

  virtual u32 GetMapSize(void) { return map_size; }

  virtual int GetShmID(void) { return shmid; }

  feedback::InplaceMemoryFeedback GetFeedback(void) {
    return feedback::InplaceMemoryFeedback(trace_bits, map_size, lock);
  }

  long GetLockUseCount(void) { return lock.use_count(); }

 protected:
  // FIXME: we want to change the type of these variables to u64.
  // But to do this, we have to modify InplaceFeedback and everything using it.
  const u32 map_size;

  std::shared_ptr<u8> lock;

 private:
  int shmid;
};

}  // namespace fuzzuf::coverage

#endif  // FUZZUF_INCLUDE_COVERAGE_SHM_COV_ATTACHER_HPP
