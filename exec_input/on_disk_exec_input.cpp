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
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"

#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::exec_input {

class ExecInput;

OnDiskExecInput::OnDiskExecInput(const fs::path& path, bool hardlinked)
    : ExecInput(), path(path), hardlinked(hardlinked) {}

OnDiskExecInput::OnDiskExecInput(OnDiskExecInput&& orig)
    : ExecInput(std::move(orig)),
      path(std::move(orig.path)),
      hardlinked(orig.hardlinked) {}

OnDiskExecInput& OnDiskExecInput::operator=(OnDiskExecInput&& orig) {
  ExecInput::operator=(std::move(orig));
  path = std::move(orig.path);
  hardlinked = orig.hardlinked;
  return *this;
}

void OnDiskExecInput::ReallocBufIfLack(u32 new_len) {
  if (!buf || new_len > len) {
    buf.reset(new u8[new_len], [](u8* p) {
      if (p) delete[] p;
    });
  }
  len = new_len;
}

void OnDiskExecInput::LoadIfNotLoaded(void) {
  if (buf) return;
  Load();
}

void OnDiskExecInput::Load(void) {
  ReallocBufIfLack(fs::file_size(path));

  int fd = fuzzuf::utils::OpenFile(path.string(), O_RDONLY);
  fuzzuf::utils::ReadFile(fd, buf.get(), len);
  fuzzuf::utils::CloseFile(fd);
}

void OnDiskExecInput::Unload(void) { buf.reset(); }

void OnDiskExecInput::Save(void) {
  if (hardlinked) {
    fuzzuf::utils::DeleteFileOrDirectory(path.string());
    hardlinked = false;
  }

  int fd = fuzzuf::utils::OpenFile(path.string(), O_WRONLY | O_CREAT | O_TRUNC,
                                   0600);
  fuzzuf::utils::WriteFile(fd, buf.get(), len);
  fuzzuf::utils::CloseFile(fd);
}

void OnDiskExecInput::OverwriteKeepingLoaded(const u8* new_buf, u32 new_len) {
  ReallocBufIfLack(new_len);
  std::memcpy(buf.get(), new_buf, len);
  Save();
}

void OnDiskExecInput::OverwriteKeepingLoaded(std::unique_ptr<u8[]>&& new_buf,
                                             u32 new_len) {
  buf.reset(new_buf.release());

  len = new_len;
  Save();
}

void OnDiskExecInput::OverwriteThenUnload(const u8* new_buf, u32 new_len) {
  buf.reset();

  int fd = fuzzuf::utils::OpenFile(path.string(), O_WRONLY | O_CREAT | O_TRUNC,
                                   0600);
  fuzzuf::utils::WriteFile(fd, new_buf, new_len);
  fuzzuf::utils::CloseFile(fd);
}

void OnDiskExecInput::OverwriteThenUnload(std::unique_ptr<u8[]>&& new_buf,
                                          u32 new_len) {
  auto will_delete = std::move(new_buf);
  OverwriteThenUnload(will_delete.get(), new_len);
}

void OnDiskExecInput::LoadByMmap(void) {
  int fd = fuzzuf::utils::OpenFile(path.string(), O_RDONLY);
  auto file_len = fs::file_size(path);

  auto raw_buf = static_cast<u8*>(
      mmap(nullptr, file_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));

  fuzzuf::utils::CloseFile(fd);

  if (raw_buf == MAP_FAILED) {
    ERROR("Unable to mmap '%s' : %s", path.c_str(), strerror(errno));
  }

  buf.reset(raw_buf, [file_len](u8* p) {
    if (p) munmap(p, file_len);
  });
  len = file_len;
}

bool OnDiskExecInput::Link(const fs::path& dest_path) {
  return link(path.c_str(), dest_path.c_str()) == 0;
}

void OnDiskExecInput::Copy(const fs::path& dest_path) {
  fuzzuf::utils::CopyFile(path.string(), dest_path.string());
}

bool OnDiskExecInput::LinkAndRefer(const fs::path& new_path) {
  if (!Link(new_path)) return false;
  path = new_path;
  hardlinked = true;
  return true;
}

void OnDiskExecInput::CopyAndRefer(const fs::path& new_path) {
  // don't want to overwrite the content if new_path is a hardlink
  fuzzuf::utils::DeleteFileOrDirectory(new_path.string());
  Copy(new_path);
  path = new_path;
  hardlinked = false;
}

const fs::path& OnDiskExecInput::GetPath(void) const { return path; }

}  // namespace fuzzuf::exec_input
