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
 * @file afl_executor_interface.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */

#ifndef FUZZUF_INCLUDE_EXECUTOR_AFL_EXECUTOR_INTERFACE_HPP
#define FUZZUF_INCLUDE_EXECUTOR_AFL_EXECUTOR_INTERFACE_HPP

#include <memory>

#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::executor {

/**
 * @class AFLExecutorInterface
 * @brief Represents minimal requirements for an AFL-capable executor.
 *
 * @details The executor for AFL must have the methods declared in this class.
 * This class is to perform type erasure for the executor class to abstract
 * the executor on the algortihms. We found that the boost's type_erasure does
 * not meet our needs, so we implemented our own type erasure.
 *
 * @note An AFL-capable executor must have the following functions:
 * - void Run(const u8 *buf, u32 len, u32 timeout_ms)
 * - InplaceMemoryFeedback GetAFLFeedback()
 * - ExitStatusFeedback GetExitStatusFeedback()
 * - void ReceiveStopSignal()
 */
class AFLExecutorInterface {
 public:
  template <class T>
  AFLExecutorInterface(const std::shared_ptr<T> &executor)
      : _container(new DynContainerDerived<T>(executor)) {}

  template <class T>
  AFLExecutorInterface(std::shared_ptr<T> &&executor) noexcept
      : _container(new DynContainerDerived<T>(std::move(executor))) {}

  AFLExecutorInterface(const AFLExecutorInterface &) = delete;
  AFLExecutorInterface(AFLExecutorInterface &&) = delete;
  AFLExecutorInterface &operator=(const AFLExecutorInterface &) = delete;
  AFLExecutorInterface &operator=(AFLExecutorInterface &&) = delete;
  AFLExecutorInterface() = delete;

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

  /// @brief Gets an exit status of last execution.
  /// @return An exit status of last execution.
  feedback::ExitStatusFeedback GetExitStatusFeedback() {
    return _container->GetExitStatusFeedback();
  }

  /// @brief A callback function called when the fuzzer receives a stop signal.
  void ReceiveStopSignal() { _container->ReceiveStopSignal(); }

 private:
  class DynContainerBase {
   public:
    virtual ~DynContainerBase() {}
    virtual void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) = 0;
    virtual feedback::InplaceMemoryFeedback GetAFLFeedback() = 0;
    virtual feedback::ExitStatusFeedback GetExitStatusFeedback() = 0;
    virtual void ReceiveStopSignal() = 0;
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

    feedback::ExitStatusFeedback GetExitStatusFeedback() {
      return _executor->GetExitStatusFeedback();
    }

    void ReceiveStopSignal() { return _executor->ReceiveStopSignal(); }

   private:
    std::shared_ptr<T> _executor;
  };

  std::unique_ptr<DynContainerBase> _container;
};

}  // namespace fuzzuf::executor

#endif  // FUZZUF_INCLUDE_EXECUTOR_AFL_EXECUTOR_INTERFACE_HPP
