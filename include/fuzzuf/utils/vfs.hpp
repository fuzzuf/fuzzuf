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
#ifndef FUZZUF_INCLUDE_UTILS_VFS_HPP
#define FUZZUF_INCLUDE_UTILS_VFS_HPP
#include <fcntl.h>
#include <fstream>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"

namespace fuzzuf::utils::vfs {

class VFS {
public:
  VFS(
    std::vector< fs::path > &&allowed_path_
  );
  const std::vector< fs::path > &GetAllowedPath() const { return *allowed_path; }
  fs::path CurrentPath() const;
  void CurrentPath( const fs::path &p );
  fs::path Absolute( const fs::path &p ) const;
  fs::path Relative( const fs::path &p ) const;
  std::optional< fs::path > IsAllowedPath( const fs::path &p ) const;
  fs::path SanitizePath( const fs::path &p ) const;

  virtual fs::path ReadSymlink( const fs::path &p ) const = 0;
  virtual void Copy(const fs::path& from, const fs::path& to) = 0; 
  virtual void Copy(const fs::path& from, const fs::path& to, fs::copy_options options) = 0;
  virtual bool CopyFile(const fs::path& from, const fs::path& to) = 0;
  virtual bool CopyFile(const fs::path& from, const fs::path& to, fs::copy_options options) = 0;
  virtual void CopySymlink(const fs::path& existing_symlink, const fs::path& new_symlink) = 0;
  virtual void CreateDirectory(const fs::path& p) = 0;
  virtual bool CreateDirectory(const fs::path& p, const fs::path& existing_p) = 0;
  virtual bool CreateDirectories(const fs::path& p) = 0;
  virtual void CreateDirectorySymlink(const fs::path& to, const fs::path& new_symlink) = 0;
  virtual void CreateHardLink(const fs::path& to, const fs::path& new_hard_link) = 0;
  virtual void CreateSymlink(const fs::path& to, const fs::path& new_symlink) = 0;
  virtual void Permissions(const fs::path& p, fs::perms prms, fs::perm_options opts=fs::perm_options::replace) = 0;
  virtual bool Remove(const fs::path& p) = 0;
  virtual std::uintmax_t RemoveAll(const fs::path& p) = 0;
  virtual void Rename(const fs::path& old_p, const fs::path& new_p) = 0;
  virtual void ResizeFile(const fs::path& p, std::uintmax_t new_size) = 0;
  virtual bool Exists(const fs::path& p) = 0;
  virtual bool Equivalent(const fs::path& p1, const fs::path& p2) = 0;
  virtual std::uintmax_t FileSize(const fs::path& p) = 0;
  virtual std::uintmax_t HardLinkCount(const fs::path& p) = 0;
  virtual bool IsRegularFile(const fs::path& p) = 0;
  virtual bool IsDirectory(const fs::path& p) = 0;
  virtual bool IsSymlink(const fs::path& p) = 0;
  virtual bool IsBlockFile(const fs::path& p) = 0;
  virtual bool IsCharacterFile(const fs::path& p) = 0;
  virtual bool IsFifo(const fs::path& p) = 0;
  virtual bool IsSocket(const fs::path& p) = 0;
  virtual bool IsOther(const fs::path& p) = 0;
  virtual bool IsEmpty(const fs::path& p) = 0;
  virtual fs::file_time_type LastWriteTime(const fs::path& p) = 0;
  virtual fs::space_info Space(const fs::path& p) = 0;
  virtual mapped_file_t Mmap( const fs::path&, unsigned int flags, bool populate ) = 0;
protected:
  fs::path current_workdir;
  std::shared_ptr< std::vector< fs::path > > allowed_path;
};

class LocalFilesystem : public VFS {
public:
  LocalFilesystem(
    std::vector< fs::path > &&allowed_path_
  );
  virtual fs::path ReadSymlink( const fs::path &p ) const override;
  virtual void Copy(const fs::path& from, const fs::path& to) override; 
  virtual void Copy(const fs::path& from, const fs::path& to, fs::copy_options options) override;
  virtual bool CopyFile(const fs::path& from, const fs::path& to) override;
  virtual bool CopyFile(const fs::path& from, const fs::path& to, fs::copy_options options) override;
  virtual void CopySymlink(const fs::path& existing_symlink, const fs::path& new_symlink) override;
  virtual void CreateDirectory(const fs::path& p) override;
  virtual bool CreateDirectory(const fs::path& p, const fs::path& existing_p) override;
  virtual bool CreateDirectories(const fs::path& p) override;
  virtual void CreateDirectorySymlink(const fs::path& to, const fs::path& new_symlink) override;
  virtual void CreateHardLink(const fs::path& to, const fs::path& new_hard_link) override;
  virtual void CreateSymlink(const fs::path& to, const fs::path& new_symlink) override;
  virtual void Permissions(const fs::path& p, fs::perms prms, fs::perm_options opts=fs::perm_options::replace) override;
  virtual bool Remove(const fs::path& p) override;
  virtual std::uintmax_t RemoveAll(const fs::path& p) override;
  virtual void Rename(const fs::path& old_p, const fs::path& new_p) override;
  virtual void ResizeFile(const fs::path& p, std::uintmax_t new_size) override;
  virtual bool Exists(const fs::path& p) override;
  virtual bool Equivalent(const fs::path& p1, const fs::path& p2) override;
  virtual std::uintmax_t FileSize(const fs::path& p) override;
  virtual std::uintmax_t HardLinkCount(const fs::path& p) override;
  virtual bool IsRegularFile(const fs::path& p) override;
  virtual bool IsDirectory(const fs::path& p) override;
  virtual bool IsSymlink(const fs::path& p) override;
  virtual bool IsBlockFile(const fs::path& p) override;
  virtual bool IsCharacterFile(const fs::path& p) override;
  virtual bool IsFifo(const fs::path& p) override;
  virtual bool IsSocket(const fs::path& p) override;
  virtual bool IsOther(const fs::path& p) override;
  virtual bool IsEmpty(const fs::path& p) override;
  virtual fs::file_time_type LastWriteTime(const fs::path& p) override;
  virtual fs::space_info Space(const fs::path& p) override;
  virtual mapped_file_t Mmap( const fs::path&, unsigned int flags, bool populate ) override;
  
  fs::directory_iterator OpenDirectory( const fs::path &p );
  fs::recursive_directory_iterator OpenDirectoryRecursive( const fs::path &p );

  std::fstream Open( const fs::path&, std::ios_base::openmode mode );
};

namespace adaptor {
template< typename Base >
class Shared : public Base {
public:
  template< typename ...Args >
  Shared(
    std::shared_ptr< void > &&p_,
    Args ...args
  ) :
    Base( std::forward< Args >( args )... ),
    p( p_ ) {}
private:
  std::shared_ptr< void > p;
};
namespace detail {
  struct SharedParams {
    std::shared_ptr< void > p;
  };
};
struct SharedTag {
  template< typename T >
  detail::SharedParams operator()( T p ) const {
    return detail::SharedParams{ std::forward< T >( p ) };
  }
};
constexpr SharedTag shared;
namespace detail {
  template< typename Base >
  Shared< Base > operator|( Base &&b, detail::SharedParams &&p ) {
    return Shared< Base >( std::move( p.p ), std::move( b ) );
  }
  template< typename Base >
  Shared< Base > operator|( Base &&b, const detail::SharedParams &p ) {
    return Shared< Base >( p.p, std::move( b ) );
  }
}

template< typename Base >
class ReadOnce {
public:
  template< typename ...Args >
  ReadOnce( Args ...args ) :
    base( std::forward< Args >( args )... ) {}
  const std::vector< fs::path > &GetAllowedPath() const {
    return base.GetAllowedPath();
  }
  std::vector< std::pair< fs::path, mapped_file_t > >
  MmapAll() {
    std::vector<std::pair<fs::path, fuzzuf::utils::mapped_file_t>> files;
    std::vector< fs::path > path_to_remove;
    for (const auto &root_dir : GetAllowedPath()) {
      for (const auto &de : base.OpenDirectoryRecursive( root_dir ) ) {
        if ( base.IsRegularFile( de.path() ) && base.FileSize( de.path() ) != 0u ) {
          auto filename = de.path().string();
          auto mapped = base.Mmap(filename, O_RDONLY, false);
          files.push_back(std::make_pair(
                std::move( filename ), std::move( mapped ) ));
          path_to_remove.push_back( de.path() );
        }
      }
    }
    for( const auto &p: path_to_remove ) {
      base.Remove( p );
    }
    files.shrink_to_fit();
    return files;
  }
  void RemoveAll() {
    std::vector< fs::path > path_to_remove;
    for (const auto &root_dir : GetAllowedPath()) {
      for (const auto &de : base.OpenDirectoryRecursive( root_dir ) ) {
        if ( base.IsRegularFile( de.path() ) && base.FileSize( de.path() ) != 0u ) {
          path_to_remove.push_back( de.path() );
        }
      }
    }
    for( const auto &p: path_to_remove ) {
      base.Remove( p );
    }
  }
private:
  Base base;
};
namespace detail {
  struct ReadOnceParams {};
  template< typename Base >
  ReadOnce< Base > operator|( Base &&b, const detail::ReadOnceParams& ) {
    return ReadOnce< Base >( std::move( b ) );
  }
}
constexpr detail::ReadOnceParams read_once;

}

}

#endif

