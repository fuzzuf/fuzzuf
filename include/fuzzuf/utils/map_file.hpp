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
#ifndef FUZZUF_INCLUDE_UTILS_MAP_FILE_HPP
#define FUZZUF_INCLUDE_UTILS_MAP_FILE_HPP
#include "fuzzuf/utils/shared_range.hpp"
#include <boost/range/iterator_range.hpp>
#include <cstdint>
#include <memory>
namespace fuzzuf::utils {
using mapped_file_t = boost::iterator_range<
    range::shared_iterator<uint8_t *, std::shared_ptr<uint8_t>>>;

/**
 * @fn
 * filenameで指定されたファイルをmmapして、mmapした領域をshared_rangeで返す
 * @brief
 * filenameで指定されたファイルをmmapして、mmapした領域をshared_rangeで返す
 * @param filename ファイル名
 * @param flags ファイルをopen(2)する際に渡すフラグ
 * @param populate
 * trueの場合mmapと同時に全てのページをメモリに乗せる事を要求する
 * @return mmapされた領域のrange
 */
auto map_file(const std::string &filename, unsigned int flags, bool populate)
    -> mapped_file_t;

} // namespace fuzzuf::utils
#endif
