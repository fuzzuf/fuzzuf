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
#include "fuzzuf/exec_input/on_memory_exec_input.hpp"

#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::exec_input {

class ExecInput;

OnMemoryExecInput::OnMemoryExecInput(const u8* orig_buf, u32 len)
    : ExecInput(orig_buf, len) {}

OnMemoryExecInput::OnMemoryExecInput(std::unique_ptr<u8[]>&& orig_buf, u32 len)
    : ExecInput(std::move(orig_buf), len) {}

OnMemoryExecInput::OnMemoryExecInput(OnMemoryExecInput&& orig)
    : ExecInput(std::move(orig)) {}

OnMemoryExecInput& OnMemoryExecInput::operator=(OnMemoryExecInput&& orig) {
  ExecInput::operator=(std::move(orig));
  return *this;
}

void OnMemoryExecInput::LoadIfNotLoaded(void) {}
void OnMemoryExecInput::Load(void) {}
void OnMemoryExecInput::Unload(void) {}
void OnMemoryExecInput::Save(void) {}

void OnMemoryExecInput::OverwriteKeepingLoaded(const u8* new_buf, u32 new_len) {
  buf.reset(new u8[new_len]);
  len = new_len;
  std::memcpy(buf.get(), new_buf, len);
}

void OnMemoryExecInput::OverwriteKeepingLoaded(std::unique_ptr<u8[]>&& new_buf,
                                               u32 new_len) {
  buf.reset(new_buf.release());
  len = new_len;
}

void OnMemoryExecInput::OverwriteThenUnload(const u8* new_buf, u32 new_len) {
  OverwriteKeepingLoaded(new_buf, new_len);  // same
}

void OnMemoryExecInput::OverwriteThenUnload(std::unique_ptr<u8[]>&& new_buf,
                                            u32 new_len) {
  OverwriteKeepingLoaded(std::move(new_buf), new_len);  // same
}

void OnMemoryExecInput::SaveToFile(const fs::path& path) {
  int fd = fuzzuf::utils::OpenFile(path.string(), O_WRONLY | O_CREAT, 0600);
  fuzzuf::utils::WriteFile(fd, buf.get(), len);
  fuzzuf::utils::CloseFile(fd);
}

}  // namespace fuzzuf::exec_input
