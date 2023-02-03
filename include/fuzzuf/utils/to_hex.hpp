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
 * @file to_hex.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_TO_HEX_HPP
#define FUZZUF_INCLUDE_UTILS_TO_HEX_HPP
#include <cstdint>
#include <string>
#include <vector>
namespace fuzzuf::utils {
/**
 * Serialize binary data into stringized hexadecimal numbers
 * @param message Destination
 * @param range Binary data to serialize
 */
void toHex(std::string &message, const std::vector<std::uint8_t> &range);
/**
 * Serialize address into stringized hexadecimal number
 * @param message Destination
 * @param value Address to serialize
 */
void toHex(std::string &message, std::uintptr_t value);
}  // namespace fuzzuf::utils
#endif
