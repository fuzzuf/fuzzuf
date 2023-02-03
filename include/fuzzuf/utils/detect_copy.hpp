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
 * @file detect_copy.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_DETECT_COPY_HPP
#define FUZZUF_INCLUDE_UTILS_DETECT_COPY_HPP

namespace fuzzuf::utils {
template <typename T>
class DetectCopy : public T {
 public:
  using T::T;
  DetectCopy(const DetectCopy &) = delete;
  DetectCopy &operator=(const DetectCopy &) = delete;
  DetectCopy(DetectCopy &&) = default;
  DetectCopy &operator=(DetectCopy &&) = default;
  operator T &() { return *this; }
  operator const T &() const { return *this; }
};
}  // namespace fuzzuf::utils

#endif
