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

#include <memory>

#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"
#include "fuzzuf/exec_input/on_memory_exec_input.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::exec_input {

class ExecInput;
class OnDiskExecInput;
class OnMemoryExecInput;

// TODO: maybe it would be more convenient
// if we provide OnDiskExecInputSet, OnMemoryExecInputSet, ...

class ExecInputSet {
 public:
  template <class Derived, class... Args>
  std::shared_ptr<Derived> CreateInput(Args&&... args) {
    std::shared_ptr<Derived> new_input(
        new Derived(std::forward<Args>(args)...));
    elems[new_input->GetID()] = new_input;
    return new_input;
  }

  template <class... Args>
  std::shared_ptr<OnDiskExecInput> CreateOnDisk(Args&&... args) {
    return CreateInput<OnDiskExecInput>(std::forward<Args>(args)...);
  }

  template <class... Args>
  std::shared_ptr<OnMemoryExecInput> CreateOnMemory(Args&&... args) {
    return CreateInput<OnMemoryExecInput>(std::forward<Args>(args)...);
  }

  ExecInputSet();
  ~ExecInputSet();

  size_t size(void);
  utils::NullableRef<ExecInput> get_ref(u64 id);
  std::shared_ptr<ExecInput> get_shared(u64 id);
  void erase(u64 id);

  std::vector<u64> get_ids(void);

 private:
  // key: input->id, val: input
  std::unordered_map<u64, std::shared_ptr<ExecInput>> elems;
};

}  // namespace fuzzuf::exec_input
