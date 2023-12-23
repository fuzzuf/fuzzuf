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
 * @file create_shared_memory.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_CREATE_SHARED_MEMORY_HPP
#define FUZZUF_INCLUDE_UTILS_CREATE_SHARED_MEMORY_HPP

#include <boost/range/iterator_range.hpp>
#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzzuf/utils/shared_range.hpp"

namespace fuzzuf::utils {
/**
 * Create shared memory with required size, map it to current process, serialize
 * fd in environment variable style, then return both serialized fd and mapped
 * range.
 * @param name environment variable name
 * @param size size of shared memory in bytes
 * @return pair of serialized fd and range
 */
std::pair<std::string,
          boost::iterator_range<fuzzuf::utils::range::shared_iterator<
              std::uint8_t *, std::shared_ptr<void> > > >
create_shared_memory(const std::string &name, std::size_t size);
}  // namespace fuzzuf_cc::utils

#endif
