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
 * @file check_if_string_is_decimal.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once
#include <string>

namespace fuzzuf::utils {
// Check if non-decimal charactors does not exists to perform strict string to
// int conversion
bool CheckIfStringIsDecimal(std::string &str);

bool CheckIfStringIsDecimal(const char *cstr);

}  // namespace fuzzuf::utils
