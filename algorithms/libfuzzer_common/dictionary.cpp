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
 * @file dictionary.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"

#include <iostream>

#include "fuzzuf/utils/afl_dict_parser.hpp"

namespace fuzzuf::algorithm::libfuzzer::dictionary {

/**
 * Load AFL compatible dictionary from specified file.
 * If dest has initial values, loaded contents are inserted at end of existing
 * entries.
 * @param filename Filename of dictionary
 * @param dest Static dictionary to store loaded entries
 * @param eout Callable with one string argument to display error message on
 * parse failure
 */
void Load(const std::string &filename_, StaticDictionary &dest, bool strict,
          const std::function<void(std::string &&)> &eout) {
  utils::dictionary::LoadAFLDictionary(filename_, dest, strict, eout);
}

/**
 * Load AFL compatible dictionary from specified file.
 * If dest has initial values, loaded contents are inserted at end of existing
 * entries.
 * @param filename Filename of dictionary
 * @param dest Dynamic dictionary to store loaded entries
 * @param eout Callable with one string argument to display error message on
 * parse failure
 */
void Load(const std::string &filename_, DynamicDictionary &dest, bool strict,
          const std::function<void(std::string &&)> &eout) {
  utils::dictionary::LoadAFLDictionary(filename_, dest, strict, eout);
}

/**
 * Load AFL compatible dictionary files specified by paths.
 * If dest has initial values, loaded contents are inserted at end of existing
 * entries.
 * @param paths Range of path to dictionary file
 * @param dest Static dictionary to store loaded entries
 * @param eout Callable with one string argument to display error message on
 * parse failure
 */
void Load(const std::vector<fs::path> &paths, StaticDictionary &dest,
          bool strict, const std::function<void(std::string &&)> &eout) {
  for (const auto &path : paths) {
    Load(path.string(), dest, strict, eout);
  }
}

/**
 * Load AFL compatible dictionary files specified by paths.
 * If dest has initial values, loaded contents are inserted at end of existing
 * entries.
 * @param paths Range of path to dictionary file
 * @param dest Dynamic dictionary to store loaded entries
 * @param eout Callable with one string argument to display error message on
 * parse failure
 */
void Load(const std::vector<fs::path> &paths, DynamicDictionary &dest,
          bool strict, const std::function<void(std::string &&)> &eout) {
  for (const auto &path : paths) {
    Load(path.string(), dest, strict, eout);
  }
}

}  // namespace fuzzuf::algorithm::libfuzzer::dictionary
