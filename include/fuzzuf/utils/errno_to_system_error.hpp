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
 * @file errno_to_system_error.hpp.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_ERRNO_TO_SYSTEM_ERROR_HPP
#define FUZZUF_INCLUDE_UTILS_ERRNO_TO_SYSTEM_ERROR_HPP
#include <string>
#include <system_error>
namespace fuzzuf::utils {
/**
 * Convert errno value to corresponding std::system_error
 * If the direct corresponding code is not available, the code which has close
 * meaning is used
 */
auto errno_to_system_error(int e) -> std::system_error;
auto errno_to_system_error(int e, const char *) -> std::system_error;
auto errno_to_system_error(int e, const std::string &) -> std::system_error;

}  // namespace fuzzuf::utils
#endif
