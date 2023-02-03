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
#include <algorithm>
#include <fuzzuf/algorithms/afl/afl_dict_data.hpp>
#include <fuzzuf/utils/afl_dict_parser.hpp>

namespace fuzzuf::algorithm::afl::dictionary {

/**
 * Loads an AFL dictionary specified by filename into dest
 * If dest already has its elements, the content loaded is inserted after them
 * @brief Load AFL dictionary specified by filename to dest
 * @param filename The name of the file
 * @param dest Where to output the content loaded
 * @param eout A callback called with an error message as a string when failed
 * to parse file
 */
void load(const std::string &filename_, std::vector<AFLDictData> &dest,
          bool strict, const std::function<void(std::string &&)> &eout) {
  utils::dictionary::LoadAFLDictionary(filename_, dest, strict, eout);
}

void SortDictByLength(std::vector<AFLDictData> &dict) {
  std::sort(dict.begin(), dict.end(), [](const auto &l, const auto &r) {
    return l.data.size() < r.data.size();
  });
}

}  // namespace fuzzuf::algorithm::afl::dictionary
