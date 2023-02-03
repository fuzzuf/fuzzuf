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
 * @file interprocess_shared_object.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_INTERPROCESS_SHARED_OBJECT_HPP
#define FUZZUF_INCLUDE_UTILS_INTERPROCESS_SHARED_OBJECT_HPP
#include <sys/mman.h>

#include <boost/range/iterator_range.hpp>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>

#include "fuzzuf/utils/shared_range.hpp"

namespace fuzzuf::utils::interprocess {

/**
 * Generate instance of T that is shared with child processes
 * T must satisfy trivially copyable concept
 * The instance is initialized by argument values
 *
 * The sharing is achieved by creating mmaped memory with
 * MAP_SHARED|MAP_ANNONYMOUS Due to this implementation, even if the type T is
 * smaller than page size, at least one page is allocated Furthermore, calling
 * this function definitely cause system call For those reason, many small type
 * values should be tied into one structure and call create_shared_object just
 * once
 *
 * The return value type is shared_ptr< T > with munmapping deleter
 *
 * If mmap failed for some reason ( for example, out of memory ), std::bad_alloc
 * is thrown
 */
template <typename T>
auto create_shared_object(const T &v)
    -> std::enable_if_t<std::is_trivially_copyable_v<T>, std::shared_ptr<T>> {
  auto addr = mmap(nullptr, sizeof(T), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (addr == reinterpret_cast<void *>(std::intptr_t(-1)))
    throw std::bad_alloc();
  return std::shared_ptr<T>(new (addr) T(v),
                            [addr](auto) { munmap(addr, sizeof(T)); });
}

}  // namespace fuzzuf::utils::interprocess
#endif
