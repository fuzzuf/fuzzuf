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
/**
 * @file map_file.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/map_file.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <boost/scope_exit.hpp>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>

namespace fuzzuf::utils {

auto map_file(const std::string &filename, unsigned int flags, bool populate)
    -> mapped_file_t {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
  int fd = open(filename.c_str(), flags);
  // NOLINTEND(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
  if (fd == -1) {
    throw std::system_error(errno, std::generic_category(), filename);
  }
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions,cppcoreguidelines-pro-type-vararg,hicpp-vararg,misc-non-private-member-variables-in-classes,hicpp-member-init)
  BOOST_SCOPE_EXIT(&fd) { close(fd); }
  BOOST_SCOPE_EXIT_END
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast,cppcoreguidelines-pro-type-member-init,cppcoreguidelines-special-member-functions,hicpp-explicit-conversions,cppcoreguidelines-pro-type-vararg,hicpp-vararg,misc-non-private-member-variables-in-classes,hicpp-member-init)

  size_t file_size = 0;
  {
    struct stat stat_;
    if (fstat(fd, &stat_) == -1) {
      throw std::system_error(errno, std::generic_category(), filename);
    }
    file_size = stat_.st_size;
  }

  unsigned int map_prot = 0U;
  unsigned int map_flags = 0U;
  if ((flags & O_RDONLY) == O_RDONLY) {
    map_prot = PROT_READ;
    map_flags = MAP_PRIVATE;
  } else if ((flags & O_WRONLY) == O_WRONLY) {
    map_prot = PROT_WRITE;
    map_flags = MAP_SHARED;
  } else if ((flags & O_RDWR) == O_RDWR) {
    map_prot = PROT_READ | PROT_WRITE;
    map_flags = MAP_SHARED;
  }

  constexpr unsigned int kilo_in_binary = 1024U;
  constexpr unsigned int huge_tlb_threshold =
      2U * kilo_in_binary * kilo_in_binary;
  if (populate) {
    map_flags |= MAP_POPULATE;
  }
  if (file_size >= huge_tlb_threshold) {
    map_flags |= MAP_HUGETLB;
  }

  void *addr = mmap(nullptr, file_size, map_prot, map_flags, fd, 0);
  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
  if (addr == reinterpret_cast<void *>(std::intptr_t(-1))) {
    // カーネルがhugepageをサポートしていない可能性がある為、hugepageを使わずにmmapし直す
    if ((map_flags & MAP_HUGETLB) != 0) {
      map_flags ^= MAP_HUGETLB;
      addr = mmap(nullptr, file_size, map_prot, map_flags, fd, 0);
      if (addr == reinterpret_cast<void *>(std::intptr_t(-1))) {
        throw std::system_error(errno, std::generic_category(), filename);
      }
    } else {
      throw std::system_error(errno, std::generic_category(), filename);
    }
  }

  auto *addr_ = reinterpret_cast<uint8_t *>(addr);
  std::shared_ptr<uint8_t> addr_sp(addr_, [file_size](uint8_t *p) {
    munmap(reinterpret_cast<void *>(p), file_size);
  });
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

  return boost::make_iterator_range(
      range::shared_iterator<uint8_t *, std::shared_ptr<uint8_t>>(addr_sp.get(),
                                                                  addr_sp),
      range::shared_iterator<uint8_t *, std::shared_ptr<uint8_t>>(
          std::next(addr_sp.get(), file_size), addr_sp));
}

}  // namespace fuzzuf::utils
