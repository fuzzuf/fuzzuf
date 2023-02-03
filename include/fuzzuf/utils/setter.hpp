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
 * @file setter.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_SETTER_HPP
#define FUZZUF_INCLUDE_UTILS_SETTER_HPP

#include <type_traits>
#define FUZZUF_MOVABLE \
  auto &&move() { return std::move(*this); }
#define FUZZUF_SETTER(name)                                                    \
  template <typename ArgType>                                                  \
  decltype(auto) set_##name(                                                   \
      ArgType v, std::enable_if_t<(sizeof(std::remove_reference_t<ArgType>) <= \
                                   sizeof(void *))> * = nullptr) {             \
    this->name = v;                                                            \
    return *this;                                                              \
  }                                                                            \
  template <typename ArgType>                                                  \
  decltype(auto) set_##name(                                                   \
      const ArgType &v,                                                        \
      std::enable_if_t<(sizeof(std::remove_reference_t<ArgType>) >             \
                        sizeof(void *))> * = nullptr) {                        \
    this->name = v;                                                            \
    return *this;                                                              \
  }                                                                            \
  template <typename ArgType>                                                  \
  decltype(auto) set_##name(                                                   \
      ArgType &&v,                                                             \
      std::enable_if_t<(sizeof(std::remove_reference_t<ArgType>) >             \
                        sizeof(void *))> * = nullptr) {                        \
    this->name = std::move(v);                                                 \
    return *this;                                                              \
  }                                                                            \
  template <typename... ArgType>                                               \
  decltype(auto) emplace_##name(ArgType &&...v) {                              \
    this->name =                                                               \
        std::remove_reference_t<std::remove_cv_t<decltype(this->name)>>(       \
            std::move(v)...);                                                  \
    return *this;                                                              \
  }

#endif
