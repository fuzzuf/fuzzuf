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
 * @file afl_symcc_executor_interface.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_EXECUTOR_AFL_SYMCC_EXECUTOR_INTERFACE_HPP
#define FUZZUF_INCLUDE_EXECUTOR_AFL_SYMCC_EXECUTOR_INTERFACE_HPP
#include <memory>

#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/utils/vfs/local_filesystem.hpp"

namespace fuzzuf::executor {

/**
 * @class AFLSymCCExecutorInterface
 * @brief Represents minimal requirements for a AFL_SymCC-capable executor.
 * SymCC requires only Run and access to the filesystem.
 *
 * @note A AFL_SymCC-capable executor must have the following functions.
 * - void Run(const u8 *buf, u32 len, u32 timeout_ms)
 * - fuzzuf::utils::vfs::LocalFilesystem &Filesystem() const
 */
class AFLSymCCExecutorInterface {
 public:
  template <class T>
  AFLSymCCExecutorInterface(const std::shared_ptr<T> &executor)
      : _container(new DynContainerDerived<T>(executor)) {}

  template <class T>
  AFLSymCCExecutorInterface(std::shared_ptr<T> &&executor) noexcept
      : _container(new DynContainerDerived<T>(std::move(executor))) {}

  AFLSymCCExecutorInterface(const AFLSymCCExecutorInterface &) = delete;
  AFLSymCCExecutorInterface(AFLSymCCExecutorInterface &&) = default;
  AFLSymCCExecutorInterface &operator=(const AFLSymCCExecutorInterface &) =
      delete;
  AFLSymCCExecutorInterface &operator=(AFLSymCCExecutorInterface &&) = default;
  AFLSymCCExecutorInterface() = delete;

  /// @brief Executes the executor with given inputs.
  /// @param buf A pointer to the fuzzing input.
  /// @param len Length of the fuzzing input.
  /// @param timeout_ms Execution timeout in milliseconds.
  void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) {
    _container->Run(buf, len, timeout_ms);
  }
  /**
   * Get filesystem context from the executor.
   * @return filesystem context to access directories associated with the
   * executor.
   */
  fuzzuf::utils::vfs::LocalFilesystem &Filesystem() const {
    return _container->Filesystem();
  }

 private:
  class DynContainerBase {
   public:
    virtual ~DynContainerBase() {}
    virtual void Run(const u8 *buf, u32 len, u32 timeout_ms = 0) = 0;
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
    fuzzuf::utils::vfs::LocalFilesystem &Filesystem() const override {
      return _executor->Filesystem();
    }

   private:
    std::shared_ptr<T> _executor;
  };
  std::unique_ptr<DynContainerBase> _container;
};

}  // namespace fuzzuf::executor

#endif  // FUZZUF_INCLUDE_EXECUTOR_AFL_SYMCC_EXECUTOR_INTERFACE_HPP
