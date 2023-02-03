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
 * @file to_hex.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/to_hex.hpp"

#include <boost/spirit/include/karma.hpp>
namespace fuzzuf::utils {
void toHex(std::string &message, const std::vector<std::uint8_t> &range) {
  namespace karma = boost::spirit::karma;
  karma::generate(std::back_inserter(message),
                  *karma::right_align(2, '0')[karma::hex], range);
  message += "\n";
  const auto end = std::find(range.begin(), range.end(), '\0');
  message += std::string(range.begin(), end);
  message += "\n";
}
void toHex(std::string &message, std::uintptr_t value) {
  namespace karma = boost::spirit::karma;
  static const karma::uint_generator<std::uintptr_t, 16> long_int_g;
  karma::generate(std::back_inserter(message),
                  karma::right_align(16, '0')[long_int_g], value);
}
}  // namespace fuzzuf::utils
