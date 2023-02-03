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
#include "fuzzuf/exec_input/exec_input.hpp"

#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::exec_input {

u64 ExecInput::id_counter = 0;

ExecInput::ExecInput() : id(id_counter++), len(0) {}

ExecInput::~ExecInput() {}

ExecInput::ExecInput(const u8* orig_buf, u32 len)
    : id(id_counter++), buf(new u8[len]), len(len) {
  std::memcpy(buf.get(), orig_buf, len);
}

ExecInput::ExecInput(std::unique_ptr<u8[]>&& orig_buf, u32 len)
    : id(id_counter++), buf(orig_buf.release()), len(len) {}

ExecInput::ExecInput(ExecInput&& orig)
    : id(orig.id), buf(std::move(orig.buf)), len(orig.len) {}

ExecInput& ExecInput::operator=(ExecInput&& orig) {
  id = orig.id;
  buf = std::move(orig.buf);
  len = orig.len;
  return *this;
}

u8* ExecInput::GetBuf() const { return buf.get(); }

u32 ExecInput::GetLen() const { return len; }

u64 ExecInput::GetID() const { return id; }

}  // namespace fuzzuf::exec_input
