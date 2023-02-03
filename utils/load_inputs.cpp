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
 * @file load_inputs.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/load_inputs.hpp"

#include <fcntl.h>

#include <iostream>

#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/sha1.hpp"

namespace fuzzuf::utils {
auto LoadInputs(const fs::path &dir, bool check_sha1)
    -> std::vector<utils::mapped_file_t> {
  if (!fs::is_directory(dir)) {
    ERROR("LoadInputs: Path is not directory: dir=%s", dir.c_str());
  }

  std::vector<utils::mapped_file_t> inputs;
  for (const auto &p : fs::recursive_directory_iterator(dir)) {
    if (fs::is_regular_file(p)) {
      if (check_sha1) {
        auto mapped = map_file(p.path().string(), O_RDONLY, true);
        auto sha1 = ToSerializedSha1(mapped);
        if (sha1 == p.path().filename().string()) {
          inputs.push_back(std::move(mapped));
        }
      } else {
        inputs.push_back(map_file(p.path().string(), O_RDONLY, true));
      }
    }
  }
  return inputs;
}
}  // namespace fuzzuf::utils
