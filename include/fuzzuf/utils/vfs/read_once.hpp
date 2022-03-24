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
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include <fcntl.h>
#include <type_traits>

namespace fuzzuf::utils::vfs::adaptor {

/**
 * @class ReadOnce
 * @brief This adaptor class takes other filesystem implementation as base, then
 * provides MmapAll that mmap and remove all non-empty regular files in the
 * allowed directories. This is intended to provide easy interface to receive
 * data from a process which use temporary files for inter-process
 * communication. The base filesystem implementation must meet the concepts
 * required in AdaptableToReadOnce. LocalFilesystem is one of the implementation
 * that satisfies the requirements.
 * @tparam Base base filesystem implementation
 */
#ifdef __cpp_concepts
// For C++20 concept capable compilers. This produces more precise error message
// on concept requirements failure.
template <typename T>
concept AdaptableToReadOnce = requires(T &v, const fs::path &p) {
  // Member function GetAllowedPath returns a range
  { v.GetAllowedPath() }
  ->std::ranges::range<>;
  // Element of range retrived by GetAllowedPath is a path
  { *v.GetAllowedPath().begin() }
  ->std::convertible_to<fs::path>;
  // Member function OpenDirectoryRecursive returns a range compatible iterator
  { begin(v.OpenDirectoryRecursive(p)) }
  ->std::input_iterator<>;
  // value of iterator retrived by OpenDirectoryRecursive has member function
  // path() and it returns fs::path value
  { v.OpenDirectoryRecursive(p)->path() }
  ->std::convertible_to<fs::path>;
  // Member function IsRegularFile returns a bool
  { v.IsRegularFile(p) }
  ->std::convertible_to<bool>;
  // Member function FileSize returns an integral value
  { v.FileSize(p) }
  ->std::integral<>;
  // Member function Mmap returns a mapped_file_t
  { v.Mmap(p, O_RDONLY, false) }
  ->std::convertible_to<mapped_file_t>;
  // Member function Remove is available
  {v.Remove(p)};
};
template <AdaptableToReadOnce Base> class ReadOnce {
#else
// For traditional compilers. The requirements are same as above.
template <typename T, typename Enable = void>
struct AdaptableToReadOnce : public std::false_type {};
template <typename T>
struct AdaptableToReadOnce<
    T, std::enable_if_t<
           // Member function GetAllowedPath returns a range
           range::is_range_v<decltype(std::declval<T>().GetAllowedPath())> &&
               // Element of range retrived by GetAllowedPath is a path
               std::is_convertible_v<
                   decltype(*std::declval<T>().GetAllowedPath().begin()),
                   fs::path> &&
               // Member function OpenDirectoryRecursive returns a range
               // compatible iterator
               range::is_iterator_v<decltype(
                   begin(std::declval<T>().OpenDirectoryRecursive(
                       std::declval<const fs::path &>())))> &&
               // value of iterator retrived by OpenDirectoryRecursive has
               // member function path() and it returns fs::path value
               std::is_convertible_v<
                   decltype(std::declval<T>()
                                .OpenDirectoryRecursive(
                                    std::declval<const fs::path &>())
                                ->path()),
                   fs::path> &&
               // Member function IsRegularFile returns a bool
               std::is_convertible_v<decltype(std::declval<T>().IsRegularFile(
                                         std::declval<const fs::path &>())),
                                     bool> &&
               // Member function FileSize returns an integral value
               std::is_integral_v<decltype(std::declval<T>().FileSize(
                   std::declval<const fs::path &>()))> &&
               // Member function Mmap returns a mapped_file_t
               std::is_convertible_v<decltype(std::declval<T>().Mmap(
                                         std::declval<const fs::path &>(),
                                         O_RDONLY, false)),
                                     mapped_file_t>,
           // Member function Remove is available
           void_t<decltype(std::declval<T>().Remove(
               std::declval<const fs::path &>()))>>> : public std::true_type {};
template <typename T>
constexpr bool adaptable_to_read_once_v = AdaptableToReadOnce<T>::value;
template <typename Base, typename Enable = void> class ReadOnce;
template <typename Base>
class ReadOnce<Base, std::enable_if_t<adaptable_to_read_once_v<Base>>> {
#endif
public:
  template <typename... Args>
  ReadOnce(Args &&...args) : base(std::forward<Args>(args)...) {}
  const std::vector<fs::path> &GetAllowedPath() const {
    return base.GetAllowedPath();
  }
  /**
   * mmap all non-empty regular files in the allowed directories, then remove them.
   * "all files" in the directory means the files which are contained in the range retrived by OpenDirectoryRecursive.
   * @return vector of file path and corresponding mmaped file.
   */
  std::vector<std::pair<fs::path, mapped_file_t>> MmapAll() {
    std::vector<std::pair<fs::path, fuzzuf::utils::mapped_file_t>> files;
    std::vector<fs::path> path_to_remove;
    for (const auto &root_dir : GetAllowedPath()) {
      for (const auto &de : base.OpenDirectoryRecursive(root_dir)) {
        if (base.IsRegularFile(de.path()) && base.FileSize(de.path()) != 0u) {
          auto filename = de.path().string();
          auto mapped = base.Mmap(filename, O_RDONLY, false);
          files.push_back(
              std::make_pair(std::move(filename), std::move(mapped)));
          path_to_remove.push_back(de.path());
        }
      }
    }
    for (const auto &p : path_to_remove) {
      base.Remove(p);
    }
    files.shrink_to_fit();
    return files;
  }
  /**
   * Remove all non-empty regular files in the allowed directories.
   */
  void RemoveAll() {
    std::vector<fs::path> path_to_remove;
    for (const auto &root_dir : GetAllowedPath()) {
      for (const auto &de : base.OpenDirectoryRecursive(root_dir)) {
        if (base.IsRegularFile(de.path()) && base.FileSize(de.path()) != 0u) {
          path_to_remove.push_back(de.path());
        }
      }
    }
    for (const auto &p : path_to_remove) {
      base.Remove(p);
    }
  }

private:
  Base base;
};
namespace detail {
struct ReadOnceParams {};
template <typename Base>
ReadOnce<utils::type_traits::RemoveCvrT<Base>>
operator|(Base &&b, const detail::ReadOnceParams &) {
  return ReadOnce<utils::type_traits::RemoveCvrT<Base>>(std::forward<Base>(b));
}
} // namespace detail
constexpr detail::ReadOnceParams read_once;

} // namespace fuzzuf::utils::vfs::adaptor

#endif
