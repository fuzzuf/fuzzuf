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

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::exec_input {

class ExecInput {
 public:
  static constexpr u64 INVALID_INPUT_ID = UINT64_MAX;

  // This class is the base class
  virtual ~ExecInput();

  // disable copies
  ExecInput(const ExecInput&) = delete;
  ExecInput& operator=(const ExecInput&) = delete;

  // allow moves
  ExecInput(ExecInput&&);
  ExecInput& operator=(ExecInput&&);

  virtual void LoadIfNotLoaded(void) = 0;
  virtual void Load(void) = 0;  // including reload
  virtual void Unload(void) = 0;
  virtual void Save(void) = 0;
  virtual void OverwriteKeepingLoaded(const u8* buf, u32 len) = 0;
  virtual void OverwriteKeepingLoaded(std::unique_ptr<u8[]>&& buf, u32 len) = 0;
  virtual void OverwriteThenUnload(const u8* buf, u32 len) = 0;
  virtual void OverwriteThenUnload(std::unique_ptr<u8[]>&& buf, u32 len) = 0;

  u8* GetBuf() const;
  u32 GetLen() const;
  u64 GetID() const;

 protected:
  u64 id;
  // FIXME: using shared instead of unique, only for ease of custom deletion.
  // Probably this is a bad practice.
  std::shared_ptr<u8[]> buf;
  u32 len;

  // ExecInput instances can be created only in ExecInputSet
  // (i.e. it's the factory of ExecInput)
  ExecInput();
  ExecInput(const u8*, u32);
  ExecInput(std::unique_ptr<u8[]>&&, u32);

 private:
  static u64 id_counter;
};

}  // namespace fuzzuf::exec_input
