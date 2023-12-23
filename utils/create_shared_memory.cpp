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
 * @file create_shared_memory.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/create_shared_memory.hpp"

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <boost/range/iterator_range.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "fuzzuf/utils/errno_to_system_error.hpp"
#include "fuzzuf/utils/shared_range.hpp"

namespace fuzzuf::utils {

std::pair<std::string,
          boost::iterator_range<fuzzuf::utils::range::shared_iterator<
              std::uint8_t *, std::shared_ptr<void> > > >
create_shared_memory(const std::string &name, std::size_t size) {
  const auto descriptor =
      shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | 0600);
  if (!descriptor) {
    fuzzuf::utils::errno_to_system_error(
        errno, "create_shared_memory: shmget failed");
  }
  const std::string afl_coverage_env = std::to_string(descriptor);
  std::uint8_t *begin = nullptr;
  if ((begin = reinterpret_cast<std::uint8_t *>(
           shmat(descriptor, nullptr, 0))) == nullptr) {
    shmctl(descriptor, IPC_RMID, nullptr);
    fuzzuf::utils::errno_to_system_error(
        errno, "create_shared_memory: shmat failed");
  }
  auto end = std::next(begin, size);
  std::fill(begin, end, 0);
  std::shared_ptr<void> deleter(reinterpret_cast<void *>(begin),
                                [descriptor](void *p) {
                                  shmdt(p);
                                  shmctl(descriptor, IPC_RMID, nullptr);
                                });
  return std::make_pair(
      name + '=' + afl_coverage_env,
      boost::make_iterator_range(
          fuzzuf::utils::range::shared_iterator<std::uint8_t *,
                                                   std::shared_ptr<void> >(
              begin, deleter),
          fuzzuf::utils::range::shared_iterator<std::uint8_t *,
                                                   std::shared_ptr<void> >(
              end, deleter)));
}

}  // namespace fuzzuf::utils
