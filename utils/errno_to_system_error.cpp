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
 * @file errno_to_system_error.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/errno_to_system_error.hpp"

#include <system_error>

namespace fuzzuf::utils {

auto errno_to_system_error(int e) -> std::system_error {
  // 以下のエラーコードはLinuxでは定義されているがC++標準のerrcには存在しない為、意味の近いエラーコードに置き換える
#ifdef __linux__
  if (e == ENODEV) {
    e = ENXIO;
  } else if (e == EPERM) {
    e = EACCES;
  } else if (e == EDQUOT) {
    e = ENOSPC;
  }
#endif
  return std::system_error(std::error_code(e, std::generic_category()));
}
auto errno_to_system_error(int e, const char *what) -> std::system_error {
  // 以下のエラーコードはLinuxでは定義されているがC++標準のerrcには存在しない為、意味の近いエラーコードに置き換える
#ifdef __linux__
  if (e == ENODEV) {
    e = ENXIO;
  } else if (e == EPERM) {
    e = EACCES;
  } else if (e == EDQUOT) {
    e = ENOSPC;
  }
#endif
  return std::system_error(std::error_code(e, std::generic_category()), what);
}
auto errno_to_system_error(int e, const std::string &what)
    -> std::system_error {
  // 以下のエラーコードはLinuxでは定義されているがC++標準のerrcには存在しない為、意味の近いエラーコードに置き換える
#ifdef __linux__
  if (e == ENODEV) {
    e = ENXIO;
  } else if (e == EPERM) {
    e = EACCES;
  } else if (e == EDQUOT) {
    e = ENOSPC;
  }
#endif
  return std::system_error(std::error_code(e, std::generic_category()), what);
}

}  // namespace fuzzuf::utils
