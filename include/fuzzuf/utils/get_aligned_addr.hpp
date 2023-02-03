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
 * @file get_aligned_addr.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_GET_ALIGNED_ADDR_HPP
#define FUZZUF_INCLUDE_UTILS_GET_ALIGNED_ADDR_HPP
#include <cstddef>

namespace fuzzuf::utils {
/*
 * Get minimum address that is aligned to specified alignment and not less than
 * specified address.
 * @param p address
 * @param align alignment
 * @return aligned address
 */
void *get_aligned_addr(void *p, std::size_t align);
/*
 * Get minimum offset that is aligned to specified alignment and not less than
 * specified offset.
 * @param p offset
 * @param align alignment
 * @return aligned offset
 */
std::size_t get_aligned_addr(std::size_t p, std::size_t align);
}  // namespace fuzzuf::utils
#endif
