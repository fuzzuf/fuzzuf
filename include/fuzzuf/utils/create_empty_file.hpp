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
 * @file create_empty_file.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_CREATE_EMPTY_FILE_HPP
#define FUZZUF_INCLUDE_UTILS_CREATE_EMPTY_FILE_HPP
#include <cstddef>
#include <string>
namespace fuzzuf::utils {
/**
 * Create file at the specified path
 * The created file has size of undefined data
 * If the filesystem supports sparse file, created file become sparse.
 * If the file is already exists and existing file size is smaller than size,
 * file is extended to size.
 */
void create_empty_file(const std::string &filename, std::size_t size);

}  // namespace fuzzuf::utils
#endif
