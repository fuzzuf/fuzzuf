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
#ifndef FUZZUF_INCLUDE_UTILS_VFS_VFS_HPP
#define FUZZUF_INCLUDE_UTILS_VFS_VFS_HPP
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include <fcntl.h>
#include <fstream>
#ifndef HAS_CXX_STD_FILESYSTEM
#include <chrono>
#endif

namespace fuzzuf::utils::vfs {

/**
 * @class VFS
 * @brief
 * Base class of virtual filesystem. This class provides basic path conversion
 * and path range check.
 */
class VFS {
public:
  /**
   * Constructor.
   * @param allowed_path_ list of paths which are allowed to access from this
   * VFS. If the listed path is directory, all files and directories under the
   * directory are allowed recursively. If the path is relative, that is
   * considered as the relative path from the first path in the list. The first
   * path must be an absolute path. The initial current directory of the VFS is
   * set to first path. Empty path list is valid. In that case, no any files are
   * accessible from the VFS and current directory is set to "/nowhere".
   * Duplicated or included paths are accepted. Such paths are silently ignored.
   */
  explicit VFS(std::vector<fs::path> &&allowed_path_);
  /**
   * Get allowed path list. This list doesn't contain duplicated or included
   * paths. All paths are converted into absolute. Ordered by identity.
   */
  const std::vector<fs::path> &GetAllowedPath() const { return *allowed_path; }
  /**
   * Get current directory. The value is used to convert relative path to
   * absolute path.
   */
  fs::path CurrentPath() const;
  /**
   * Set current directory. If the new path is relative, the path is converted
   * to absolute using old current directory.
   * @param p new current directory.
   */
  void CurrentPath(const fs::path &p);
  /**
   * Convert path to absolute. If the path is already absolute, this function
   * has no effects.
   * @param p path to convert
   */
  fs::path Absolute(const fs::path &p) const;
  /**
   * Convert path to relative. If the path is already relative, this function
   * has no effects.
   * @param p path to convert
   */
  fs::path Relative(const fs::path &p) const;
  /**
   * Check if the path is accessible from this VFS. If accessible, this function
   * returns the checked path in normalized and absolute form. Otherwise the
   * function returns nullopt.
   * @param p path to check
   */
  std::optional<fs::path> IsAllowedPath(const fs::path &p) const;
  /**
   * Check if the path is accessible from this VFS. If accessible, this function
   * returns the checked path in normalized and absolute form. Otherwise
   * invalid_file exception is thrown.
   * @param p path to check
   */
  fs::path SanitizePath(const fs::path &p) const;

  /*
   * Filesystem dependent operations
   */
  virtual fs::path ReadSymlink(const fs::path &p) const = 0;
  virtual void Copy(const fs::path &from, const fs::path &to) = 0;
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual void Copy(const fs::path &from, const fs::path &to,
                    fs::copy_options options) = 0;
#endif
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual bool CopyFile(const fs::path &from, const fs::path &to) = 0;
  virtual bool CopyFile(const fs::path &from, const fs::path &to,
                        fs::copy_options options) = 0;
#else
  virtual void CopyFile(const fs::path &from, const fs::path &to) = 0;
#endif
  virtual void CopySymlink(const fs::path &existing_symlink,
                           const fs::path &new_symlink) = 0;
  virtual bool CreateDirectory(const fs::path &p) = 0;
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual bool CreateDirectory(const fs::path &p,
                               const fs::path &existing_p) = 0;
#endif
  virtual bool CreateDirectories(const fs::path &p) = 0;
  virtual void CreateDirectorySymlink(const fs::path &to,
                                      const fs::path &new_symlink) = 0;
  virtual void CreateHardLink(const fs::path &to,
                              const fs::path &new_hard_link) = 0;
  virtual void CreateSymlink(const fs::path &to,
                             const fs::path &new_symlink) = 0;
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual void
  Permissions(const fs::path &p, fs::perms prms,
              fs::perm_options opts = fs::perm_options::replace) = 0;
#else
  virtual void Permissions(const fs::path &p, fs::perms prms) = 0;
#endif
  virtual bool Remove(const fs::path &p) = 0;
  virtual std::uintmax_t RemoveAll(const fs::path &p) = 0;
  virtual void Rename(const fs::path &old_p, const fs::path &new_p) = 0;
  virtual void ResizeFile(const fs::path &p, std::uintmax_t new_size) = 0;
  virtual bool Exists(const fs::path &p) = 0;
  virtual bool Equivalent(const fs::path &p1, const fs::path &p2) = 0;
  virtual std::uintmax_t FileSize(const fs::path &p) = 0;
  virtual std::uintmax_t HardLinkCount(const fs::path &p) = 0;
  virtual bool IsRegularFile(const fs::path &p) = 0;
  virtual bool IsDirectory(const fs::path &p) = 0;
  virtual bool IsSymlink(const fs::path &p) = 0;
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual bool IsBlockFile(const fs::path &p) = 0;
  virtual bool IsCharacterFile(const fs::path &p) = 0;
  virtual bool IsFifo(const fs::path &p) = 0;
  virtual bool IsSocket(const fs::path &p) = 0;
#endif
  virtual bool IsOther(const fs::path &p) = 0;
  virtual bool IsEmpty(const fs::path &p) = 0;
#ifdef HAS_CXX_STD_FILESYSTEM
  virtual fs::file_time_type LastWriteTime(const fs::path &p) = 0;
#else
  virtual std::chrono::system_clock::time_point
  LastWriteTime(const fs::path &p) = 0;
#endif
  virtual fs::space_info Space(const fs::path &p) = 0;
  virtual mapped_file_t Mmap(const fs::path &, unsigned int flags,
                             bool populate) = 0;

protected:
  VFS(const VFS &) = default;
  VFS(VFS &&) = default;
  VFS &operator=(const VFS &) = default;
  VFS &operator=(VFS &&) = default;
  fs::path current_workdir;
  std::shared_ptr<std::vector<fs::path>> allowed_path;
};

} // namespace fuzzuf::utils::vfs

#endif
