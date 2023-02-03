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
 * @file test_utils.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/test_utils.hpp"

#include <iostream>

namespace fuzzuf::algorithm::libfuzzer::test {

auto getSeed1() -> Range {
  return Range{'T', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ',
               'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x'};
}
auto getSeed2() -> Range {
  return Range{'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r', ' ', 't',
               'h', 'e', ' ', 'l', 'a', 'z', 'y', ' ', 'd', 'o', 'g'};
}
void LoadDictionary(
    fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary &dict) {
  Load(TEST_DICTIONARY_DIR "/test.dict", dict, false,
       [](std::string &&m) { std::cerr << m << std::endl; });
}

}  // namespace fuzzuf::algorithm::libfuzzer::test
