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
#ifndef FUZZUF_INCLUDE_UTILS_VFS_READ_ONCE_HPP
#define FUZZUF_INCLUDE_UTILS_VFS_READ_ONCE_HPP
#include <fcntl.h>
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"

namespace fuzzuf::utils::vfs::adaptor {

template< typename Base >
class ReadOnce {
public:
  template< typename ...Args >
  ReadOnce( Args&& ...args ) :
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
  ReadOnce< utils::type_traits::RemoveCvrT< Base > > operator|( Base &&b, const detail::ReadOnceParams& ) {
    return ReadOnce< utils::type_traits::RemoveCvrT< Base > >( std::forward< Base >( b ) );
  }
}
constexpr detail::ReadOnceParams read_once;

}

#endif

