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
 * @file get_aligned_addr.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/get_aligned_addr.hpp"

#include <cstdint>

namespace fuzzuf::utils {
std::size_t get_aligned_addr(std::size_t p, std::size_t align) {
  return (p / align + ((p % align) ? 1u : 0u)) * align;
}
void *get_aligned_addr(void *p, std::size_t align) {
  return reinterpret_cast<void *>(
      (std::intptr_t(p) / align + ((std::intptr_t(p) % align) ? 1u : 0u)) *
      align);
}
}  // namespace fuzzuf::utils
