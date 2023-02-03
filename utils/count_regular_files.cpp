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

#include "fuzzuf/utils/count_regular_files.hpp"

namespace fuzzuf::utils {

std::size_t CountRegularFiles(const fs::path &p) {
  std::size_t count = 0u;
  for (const auto &e : fs::directory_iterator(p)) {
#ifdef HAS_CXX_STD_FILESYSTEM
    if (!e.is_regular_file()) continue;
#else
    if (!fs::is_regular_file(e.path())) continue;
#endif
    ++count;
  }
  return count;
}

}  // namespace fuzzuf::utils
