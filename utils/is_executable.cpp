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
 * @file is_executable.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <unistd.h>

#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::utils {

bool is_executable(const fs::path &name) {
  if (!fs::exists(name)) return false;
  if (!fs::is_regular_file(name)) return false;
  return access(name.c_str(), X_OK) == 0;
}

}  // namespace fuzzuf::utils
