/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file map_file.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_VFS_LOCAL_FILESYSTEM_HPP
#define FUZZUF_INCLUDE_UTILS_VFS_LOCAL_FILESYSTEM_HPP
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/vfs/vfs.hpp"
#include <fcntl.h>
#include <fstream>

namespace fuzzuf::utils::vfs {

/**
 * @class LocalFilesystem
 * @brief Virtual filesystem implementation that interface to local filesystem.
 * This is a wrapper to the standard filesystem functions with path filtering.
 */
class LocalFilesystem : public VFS {
public:
  /**
   * Constructor.
   * @param allowed_path_ Only paths listed here are accessible from the VFS.
   * For more detail check fuzzuf::utils::vfs::VFS.
   * @param create If true, directories are created if the directory specified
   * by allowed_path_ is not exist. Otherwise, invalid_argument exception is
   * thrown if not exist.
   */
  explicit LocalFilesystem(std::vector<fs::path> &&allowed_path_,
                           bool create = true);
  /**
   * Copy constructor.
   * LocalFilesystem is copyable. If copied, both instance share the allowed
   * paths yet have independent current directory.
   */
  LocalFilesystem(const LocalFilesystem &) = default;
  LocalFilesystem(LocalFilesystem &&) = default;
  LocalFilesystem &operator=(const LocalFilesystem &) = default;
  LocalFilesystem &operator=(LocalFilesystem &&) = default;
  /**
   * wrapper to fs::read_symlink
   * @param p path to read
   * @return referenced path
   */
  virtual fs::path ReadSymlink(const fs::path &p) const override;
  /**
   * wrapper to fs::copy
   * @param from copy from this file
   * @param to copy to this file
   */
  virtual void Copy(const fs::path &from, const fs::path &to) override;
#ifdef HAS_CXX_STD_FILESYSTEM
  /**
   * wrapper to fs::copy
   * @param from copy from this file
   * @param to copy to this file
   */
  virtual void Copy(const fs::path &from, const fs::path &to,
                    fs::copy_options options) override;
  /**
   * wrapper to fs::copy_file
   * @param from copy from this file
   * @param to copy to this file
   * @return true if copied
   */
  virtual bool CopyFile(const fs::path &from, const fs::path &to) override;
  /**
   * wrapper to fs::copy_file
   * @param from copy from this file
   * @param to copy to this file
   * @param options copy options
   * @return true if copied
   */
  virtual bool CopyFile(const fs::path &from, const fs::path &to,
                        fs::copy_options options) override;
#else
  /**
   * wrapper to fs::copy_file
   * @param from copy from this file
   * @param to copy to this file
   * @return true if copied
   */
  virtual void CopyFile(const fs::path &from, const fs::path &to) override;
#endif
  /**
   * wrapper to fs::copy_symlink
   * @param existing_symlink copy from this symlink
   * @param new_symlink copy to this symlink
   */
  virtual void CopySymlink(const fs::path &existing_symlink,
                           const fs::path &new_symlink) override;
  /**
   * wrapper to fs::create_directory
   * @param p path of the directory
   */
  virtual bool CreateDirectory(const fs::path &p) override;
#ifdef HAS_CXX_STD_FILESYSTEM
  /**
   * wrapper to fs::create_directory
   * @param p path of the directory
   * @param existing_p copy permission from the directory
   * @param true if created
   */
  virtual bool CreateDirectory(const fs::path &p,
                               const fs::path &existing_p) override;
#endif
  /**
   * wrapper to fs::create_directories
   * @param p path to the directory
   * @param true if created
   */
  virtual bool CreateDirectories(const fs::path &p) override;
  /**
   * wrapper to fs::create_directory_symlink
   * @param to path to reference
   * @param new_symlink path to create symlink
   */
  virtual void CreateDirectorySymlink(const fs::path &to,
                                      const fs::path &new_symlink) override;
  /**
   * wrapper to fs::create_hard_link
   * @param to path to reference
   * @param new_hard_link path to create hard link
   */
  virtual void CreateHardLink(const fs::path &to,
                              const fs::path &new_hard_link) override;
  /**
   * wrapper to fs::create_symlink
   * @param to path to reference
   * @param new_symlink path to create symlink
   */
  virtual void CreateSymlink(const fs::path &to,
                             const fs::path &new_symlink) override;
  /**
   * wrapper to fs::permission
   * @param p path to modify permission
   * @param prms file access permissions
   * @param opts enum to specify how to modify permission
   */
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual void
  Permissions(const fs::path &p, fs::perms prms,
              fs::perm_options opts = fs::perm_options::replace) override;
#else
  virtual void Permissions(const fs::path &p, fs::perms prms) override;
#endif
  /**
   * wrapper to fs::remove
   * @param p path to remove
   * @return true if p is no longer exist
   */
  virtual bool Remove(const fs::path &p) override;
  /**
   * wrapper to fs::remove_all
   * @param p path to remove
   * @return number of removed files
   */
  virtual std::uintmax_t RemoveAll(const fs::path &p) override;
  /**
   * wrapper to fs::rename
   * @param old_p old file path
   * @param new_p new file path
   */
  virtual void Rename(const fs::path &old_p, const fs::path &new_p) override;
  /**
   * wrapper to fs::resize_file
   * @param p path to the file
   * @param new_size new file size
   */
  virtual void ResizeFile(const fs::path &p, std::uintmax_t new_size) override;
  /**
   * wrapper to fs::exists
   * @param p path to check
   * @return true if the file exists
   */
  virtual bool Exists(const fs::path &p) override;
  /**
   * wrapper to fs::equivalent
   * @param p1 path to compare
   * @param p2 path to compare
   * @return true if p1 and p2 refer same data on filesystem
   */
  virtual bool Equivalent(const fs::path &p1, const fs::path &p2) override;
  /**
   * wrapper to fs::file_size
   * @param p path to check
   * @return file size
   */
  virtual std::uintmax_t FileSize(const fs::path &p) override;
  /**
   * wrapper to fs::hard_link_count
   * @param p path to check
   * @return hard link count
   */
  virtual std::uintmax_t HardLinkCount(const fs::path &p) override;
  /**
   * wrapper to fs::is_regular_file
   * @param p path to check
   * @return true if p is a regular file
   */
  virtual bool IsRegularFile(const fs::path &p) override;
  /**
   * wrapper to fs::is_directory
   * @param p path to check
   * @return true if p is a directory
   */
  virtual bool IsDirectory(const fs::path &p) override;
  /**
   * wrapper to fs::is_symlink
   * @param p path to check
   * @return true if p is a symlink
   */
  virtual bool IsSymlink(const fs::path &p) override;
#ifdef HAS_CXX_STD_FILESYSTEM
  /**
   * wrapper to fs::is_block_file
   * @param p path to check
   * @return true if p is a block special file
   */
  virtual bool IsBlockFile(const fs::path &p) override;
  /**
   * wrapper to fs::is_character_file
   * @param p path to check
   * @return true if p is a character special file
   */
  virtual bool IsCharacterFile(const fs::path &p) override;
  /**
   * wrapper to fs::is_fifo
   * @param p path to check
   * @return true if p is a named pipe
   */
  virtual bool IsFifo(const fs::path &p) override;
  /**
   * wrapper to fs::is_socket
   * @param p path to check
   * @return true if p is a socket
   */
  virtual bool IsSocket(const fs::path &p) override;
  /**
   * wrapper to fs::is_other
   * @param p path to check
   * @return true if p is not a regular file nor directory nor symlink
   */
#endif
  virtual bool IsOther(const fs::path &p) override;
  /**
   * wrapper to fs::is_empty
   * @param p path to check
   * @return true if size of p is zero
   */
  virtual bool IsEmpty(const fs::path &p) override;
  /**
   * wrapper to fs::last_write_time
   * @param p path to check
   * @return last update date of p in chrono time_point
   */
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual fs::file_time_type LastWriteTime(const fs::path &p) override;
#else
  virtual std::chrono::system_clock::time_point
  LastWriteTime(const fs::path &p) override;
#endif
  /**
   * wrapper to fs::space
   * @param p check the storage which contains p
   * @return available space of the storage
   */
  virtual fs::space_info Space(const fs::path &p) override;
  /**
   * Get range of the file contents
   * @param p path to retrive
   * @param flags flags to specify mmap behavior
   * @param populate If true, load contents immediately. Otherwise, load
   * contents on demand.
   */
  virtual mapped_file_t Mmap(const fs::path &p, unsigned int flags,
                             bool populate) override;
  /**
   * Get directory traversal iterator
   * @param p path to the directory
   * @return directory traversal iterator
   */
  fs::directory_iterator OpenDirectory(const fs::path &p);
  /**
   * Get recursive directory traversal iterator
   * @param p path to the directory
   * @return recursive directory traversal iterator
   */
  fs::recursive_directory_iterator OpenDirectoryRecursive(const fs::path &p);
  /**
   * Open the file
   * @param p path to the file
   * @param mode open mode
   * @return fstream to the file
   */
  std::fstream Open(const fs::path &p, std::ios_base::openmode mode);
};

} // namespace fuzzuf::utils::vfs

#endif
