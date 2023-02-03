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
 * @file libfuzzer_executor_interface.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_EXECUTOR_LIBFUZZER_EXECUTOR_INTERFACE_HPP
#define FUZZUF_INCLUDE_EXECUTOR_LIBFUZZER_EXECUTOR_INTERFACE_HPP

#include <memory>

#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/vfs/local_filesystem.hpp"

namespace fuzzuf::executor {

/**
 * @class LibFuzzerExecutorInterface
 * @brief Represents minimal requirements for a libFuzzer-capable executor.
 *
 * @details The executor for libFuzzer must have the methods declared in this
 * class. This class is to perform type erasure for the executor class to
 * abstract the executor on the algortihms. We found that the boost's
 * type_erasure does not meet our needs, so we implemented our own type erasure.
 *
 * @note A libFuzzer-capable executor must have the following functions.
 * - void Run(const u8 *buf, u32 len, u32 timeout_ms)
 * - InplaceMemoryFeedback GetAFLFeedback()
 * - InplaceMemoryFeedback GetBBFeedback()
 * - ExitStatusFeedback GetExitStatusFeedback()
 * - fuzzuf::executor::output_t MoveStdOut()
 * - fuzzuf::executor::output_t MoveStdErr()
 */
class LibFuzzerExecutorInterface {
 public:
  template <class T>
  LibFuzzerExecutorInterface(const std::shared_ptr<T> &executor)
      : _container(new DynContainerDerived<T>(executor)) {}

  template <class T>
  LibFuzzerExecutorInterface(std::shared_ptr<T> &&executor) noexcept
      : _container(new DynContainerDerived<T>(std::move(executor))) {}

  LibFuzzerExecutorInterface(const LibFuzzerExecutorInterface &) = delete;
  LibFuzzerExecutorInterface(LibFuzzerExecutorInterface &&) = default;
  LibFuzzerExecutorInterface &operator=(const LibFuzzerExecutorInterface &) =
      delete;
  LibFuzzerExecutorInterface &operator=(LibFuzzerExecutorInterface &&) =
      default;
  LibFuzzerExecutorInterface() = delete;

  /// @brief Executes the executor with given inputs.
  /// @param buf A pointer to the fuzzing input.
  /// @param len Length of the fuzzing input.
  /// @param timeout_ms Execution timeout in milliseconds.
  void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) {
    _container->Run(buf, len, timeout_ms);
  }

  /// @brief Gets AFL-compatible hashed edge coverage bitmap.
  /// @return AFL-compatible hashed edge coverage bitmap.
  feedback::InplaceMemoryFeedback GetAFLFeedback() {
    return _container->GetAFLFeedback();
  }

  /// @brief Gets fuzzuf basic block coverage bitmap.
  /// @return fuzzuf basic block coverage bitmap.
  feedback::InplaceMemoryFeedback GetBBFeedback() {
    return _container->GetBBFeedback();
  }

  /// @brief Gets an exit status of last execution.
  /// @return An exit status of last execution.
  feedback::ExitStatusFeedback GetExitStatusFeedback() {
    return _container->GetExitStatusFeedback();
  }

  /// @brief Moves captured stdout output during the execution.
  /// @return Captured stdout output during the execution.
  fuzzuf::executor::output_t MoveStdOut() { return _container->MoveStdOut(); }

  /// @brief Moves captured stderr output during the execution.
  /// @return Captured stderr output during the execution.
  fuzzuf::executor::output_t MoveStdErr() { return _container->MoveStdErr(); }

  fuzzuf::utils::vfs::LocalFilesystem &Filesystem() const {
    return _container->Filesystem();
  }

 private:
  class DynContainerBase {
   public:
    virtual ~DynContainerBase() {}
    virtual void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) = 0;
    virtual feedback::InplaceMemoryFeedback GetAFLFeedback() = 0;
    virtual feedback::InplaceMemoryFeedback GetBBFeedback() = 0;
    virtual feedback::ExitStatusFeedback GetExitStatusFeedback() = 0;
    virtual fuzzuf::executor::output_t MoveStdOut() = 0;
    virtual fuzzuf::executor::output_t MoveStdErr() = 0;
    virtual fuzzuf::utils::vfs::LocalFilesystem &Filesystem() const = 0;
  };

  template <class T>
  class DynContainerDerived : public DynContainerBase {
   public:
    DynContainerDerived(std::shared_ptr<T> const &executor)
        : _executor(executor) {}
    DynContainerDerived(std::shared_ptr<T> &&executor) noexcept
        : _executor(std::move(executor)) {}

    void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) {
      _executor->Run(buf, len, timeout_ms);
    }

    feedback::InplaceMemoryFeedback GetAFLFeedback() {
      return _executor->GetAFLFeedback();
    }

    feedback::InplaceMemoryFeedback GetBBFeedback() {
      return _executor->GetBBFeedback();
    }

    feedback::ExitStatusFeedback GetExitStatusFeedback() {
      return _executor->GetExitStatusFeedback();
    }

    fuzzuf::executor::output_t MoveStdOut() { return _executor->MoveStdOut(); }

    fuzzuf::executor::output_t MoveStdErr() { return _executor->MoveStdErr(); }

    fuzzuf::utils::vfs::LocalFilesystem &Filesystem() const override {
      return _executor->Filesystem();
    }

   private:
    std::shared_ptr<T> _executor;
  };

  std::unique_ptr<DynContainerBase> _container;
};

}  // namespace fuzzuf::executor

#endif  // FUZZUF_INCLUDE_EXECUTOR_LIBFUZZER_EXECUTOR_INTERFACE_HPP
