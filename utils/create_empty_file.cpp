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
 * @file create_empty_file.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/create_empty_file.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/scope_exit.hpp>
#include <string>

#include "fuzzuf/utils/errno_to_system_error.hpp"

namespace fuzzuf::utils {

void create_empty_file(const std::string &filename, std::size_t size) {
  const auto fd = open(filename.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd < 0) throw errno_to_system_error(errno);

  BOOST_SCOPE_EXIT(&fd) { close(fd); }
  BOOST_SCOPE_EXIT_END

  if (lseek(fd, size, SEEK_SET) < 0) throw errno_to_system_error(errno);
}

}  // namespace fuzzuf::utils
