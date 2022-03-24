#include <algorithm>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/utils/vfs/local_filesystem.hpp>

namespace fuzzuf::utils::vfs {

LocalFilesystem::LocalFilesystem(std::vector<fs::path> &&allowed_path_,
                                 bool create)
    : VFS(std::move(allowed_path_)) {
  if (create) {
    for (const auto &p : *allowed_path) {
      fs::create_directories(p);
    }
  } else {
    if (std::find_if(allowed_path->begin(), allowed_path->end(),
                     [](const auto &p) { return !fs::exists(p); }) !=
        allowed_path->end())
      throw exceptions::invalid_argument("The path doesn't exist", __FILE__,
                                         __LINE__);
  }
}

fs::path LocalFilesystem::ReadSymlink(const fs::path &p) const {
  return fs::read_symlink(p);
}
void LocalFilesystem::Copy(const fs::path &from, const fs::path &to) {
  fs::copy(SanitizePath(from), SanitizePath(to));
}
#ifdef HAS_CXX_STD_FILESYSTEM
void LocalFilesystem::Copy(const fs::path &from, const fs::path &to,
                           fs::copy_options options) {
  fs::copy(SanitizePath(from), SanitizePath(to), options);
}
bool LocalFilesystem::CopyFile(const fs::path &from, const fs::path &to) {
  return fs::copy_file(SanitizePath(from), SanitizePath(to));
}
bool LocalFilesystem::CopyFile(const fs::path &from, const fs::path &to,
                               fs::copy_options options) {
  return fs::copy_file(SanitizePath(from), SanitizePath(to), options);
}
#else
void LocalFilesystem::CopyFile(const fs::path &from, const fs::path &to) {
  fs::copy_file(SanitizePath(from), SanitizePath(to));
}
#endif
void LocalFilesystem::CopySymlink(const fs::path &existing_symlink,
                                  const fs::path &new_symlink) {
  fs::copy_symlink(SanitizePath(existing_symlink), SanitizePath(new_symlink));
}
bool LocalFilesystem::CreateDirectory(const fs::path &p) {
  return fs::create_directory(SanitizePath(p));
}
#ifdef HAS_CXX_STD_FILESYSTEM
bool LocalFilesystem::CreateDirectory(const fs::path &p,
                                      const fs::path &existing_p) {
  return fs::create_directory(SanitizePath(p), SanitizePath(existing_p));
}
#endif
bool LocalFilesystem::CreateDirectories(const fs::path &p) {
  return fs::create_directories(SanitizePath(p));
}
void LocalFilesystem::CreateDirectorySymlink(const fs::path &to,
                                             const fs::path &new_symlink) {
  fs::create_directory_symlink(SanitizePath(to), SanitizePath(new_symlink));
}
void LocalFilesystem::CreateHardLink(const fs::path &to,
                                     const fs::path &new_hard_link) {
  fs::create_hard_link(SanitizePath(to), SanitizePath(new_hard_link));
}
void LocalFilesystem::CreateSymlink(const fs::path &to,
                                    const fs::path &new_symlink) {
  fs::create_symlink(SanitizePath(to), SanitizePath(new_symlink));
}
#ifdef HAS_CXX_STD_FILESYSTEM
void LocalFilesystem::Permissions(const fs::path &p, fs::perms prms,
                                  fs::perm_options opts) {
  fs::permissions(SanitizePath(p), prms, opts);
#else
void LocalFilesystem::Permissions(const fs::path &p, fs::perms prms) {
  fs::permissions(SanitizePath(p), prms);
#endif
}
bool LocalFilesystem::Remove(const fs::path &p) {
  return fs::remove(SanitizePath(p));
}
std::uintmax_t LocalFilesystem::RemoveAll(const fs::path &p) {
  return fs::remove_all(SanitizePath(p));
}
void LocalFilesystem::Rename(const fs::path &old_p, const fs::path &new_p) {
  fs::rename(SanitizePath(old_p), SanitizePath(new_p));
}
void LocalFilesystem::ResizeFile(const fs::path &p, std::uintmax_t new_size) {
  fs::resize_file(SanitizePath(p), new_size);
}
bool LocalFilesystem::Exists(const fs::path &p) {
  return fs::exists(SanitizePath(p));
}
bool LocalFilesystem::Equivalent(const fs::path &p1, const fs::path &p2) {
  return fs::equivalent(SanitizePath(p1), SanitizePath(p2));
}
std::uintmax_t LocalFilesystem::FileSize(const fs::path &p) {
  return fs::file_size(SanitizePath(p));
}
std::uintmax_t LocalFilesystem::HardLinkCount(const fs::path &p) {
  return fs::hard_link_count(SanitizePath(p));
}
bool LocalFilesystem::IsRegularFile(const fs::path &p) {
  return fs::is_regular_file(SanitizePath(p));
}
bool LocalFilesystem::IsDirectory(const fs::path &p) {
  return fs::is_directory(SanitizePath(p));
}
bool LocalFilesystem::IsSymlink(const fs::path &p) {
  return fs::is_symlink(SanitizePath(p));
}
#ifdef HAS_CXX_STD_FILESYSTEM
bool LocalFilesystem::IsBlockFile(const fs::path &p) {
  return fs::is_block_file(SanitizePath(p));
}
bool LocalFilesystem::IsCharacterFile(const fs::path &p) {
  return fs::is_character_file(SanitizePath(p));
}
bool LocalFilesystem::IsFifo(const fs::path &p) {
  return fs::is_fifo(SanitizePath(p));
}
bool LocalFilesystem::IsSocket(const fs::path &p) {
  return fs::is_socket(SanitizePath(p));
}
#endif
bool LocalFilesystem::IsOther(const fs::path &p) {
  return fs::is_other(SanitizePath(p));
}
bool LocalFilesystem::IsEmpty(const fs::path &p) {
  return fs::is_empty(SanitizePath(p));
}
#ifdef HAS_CXX_STD_FILESYSTEM
fs::file_time_type LocalFilesystem::LastWriteTime(const fs::path &p) {
  return fs::last_write_time(SanitizePath(p));
#else
std::chrono::system_clock::time_point
LocalFilesystem::LastWriteTime(const fs::path &p) {
  return std::chrono::system_clock::from_time_t(
      fs::last_write_time(SanitizePath(p)));
#endif
}
fs::space_info LocalFilesystem::Space(const fs::path &p) {
  return fs::space(SanitizePath(p));
}
fs::directory_iterator LocalFilesystem::OpenDirectory(const fs::path &p) {
#ifdef HAS_CXX_STD_FILESYSTEM
  return fs::directory_iterator(SanitizePath(p),
                                fs::directory_options::skip_permission_denied);
#else
  return fs::directory_iterator(SanitizePath(p));
#endif
}
fs::recursive_directory_iterator
LocalFilesystem::OpenDirectoryRecursive(const fs::path &p) {
#ifdef HAS_CXX_STD_FILESYSTEM
  return fs::recursive_directory_iterator(
      SanitizePath(p), fs::directory_options::skip_permission_denied);
#else
  return fs::recursive_directory_iterator(SanitizePath(p));
#endif
}
mapped_file_t LocalFilesystem::Mmap(const fs::path &p, unsigned int flags,
                                    bool populate) {
  return map_file(SanitizePath(p).string(), flags, populate);
}
std::fstream LocalFilesystem::Open(const fs::path &p,
                                   std::ios_base::openmode mode) {
  return std::fstream(SanitizePath(p).string(), mode);
}

} // namespace fuzzuf::utils::vfs
