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
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::exec_input {

class OnMemoryExecInput : public ExecInput {
 public:
  ~OnMemoryExecInput() {}

  // disable copies
  OnMemoryExecInput(const OnMemoryExecInput&) = delete;
  OnMemoryExecInput& operator=(const OnMemoryExecInput&) = delete;

  // allow moves
  OnMemoryExecInput(OnMemoryExecInput&&);
  OnMemoryExecInput& operator=(OnMemoryExecInput&&);

  void LoadIfNotLoaded(void);
  void Load(void);
  void Unload(void);
  void Save(void);
  void OverwriteKeepingLoaded(const u8* buf, u32 len);
  void OverwriteKeepingLoaded(std::unique_ptr<u8[]>&& buf, u32 len);
  void OverwriteThenUnload(const u8* buf, u32 len);
  void OverwriteThenUnload(std::unique_ptr<u8[]>&& buf, u32 len);

  void SaveToFile(const fs::path& path);

 private:
  // ExecInput instances can be created only in ExecInputSet
  // (i.e. it's the factory of ExecInput)
  friend class ExecInputSet;
  OnMemoryExecInput(const u8* buf, u32 len);
  OnMemoryExecInput(std::unique_ptr<u8[]>&& buf, u32 len);
};

}  // namespace fuzzuf::exec_input
