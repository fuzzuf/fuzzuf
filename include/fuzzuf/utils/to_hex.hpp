/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_UTILS_TO_HEX_HPP
#define FUZZUF_INCLUDE_UTILS_TO_HEX_HPP
#include <cstdint>
#include <string>
#include <vector>
namespace fuzzuf::utils {
/**
 * @fn
 * バイナリをhexdumpしたものを指定された文字列に書き出す
 * @param message 出力先
 * @param range ダンプするバイナリ
 */
void toHex(std::string &message, const std::vector<std::uint8_t> &range);
/**
 * @fn
 * アドレスを16進数で文字列にして、指定された文字列に書き出す
 * @param message 出力先
 * @param value アドレス
 */
void toHex(std::string &message, std::uintptr_t value);
} // namespace fuzzuf::utils
#endif
