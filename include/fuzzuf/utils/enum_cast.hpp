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
 * @file enum_cast.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_ENUM_CAST_HPP
#define FUZZUF_INCLUDE_UTILS_ENUM_CAST_HPP
#include <string>
#include <type_traits>

#include "fuzzuf/utils/check_capability.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

/**
 * Macro to generate a function that casts enum to the matched label name
 * instead of the integral value Detailed usage is available in Utils/Status.hpp
 */
#define FUZZUF_ENUM_CAST_CHECK(ns, name)                                      \
  namespace detail::enum_cast::ns {                                           \
  FUZZUF_CHECK_CAPABILITY(Has##name, has_##name, T ::name)                    \
  template <typename T>                                                       \
  auto get##name()                                                            \
      -> std::enable_if_t<std::is_enum_v<T>, decltype(T ::name)> {            \
    return T ::name;                                                          \
  }                                                                           \
  template <typename T>                                                       \
  auto get##name() -> std::enable_if_t<std::is_convertible_v<T, std::string>, \
                                       std::string> {                         \
    return #name;                                                             \
  }                                                                           \
  }

#define FUZZUF_ENUM_CAST_BEGIN(ns, fallback)                          \
  template <typename T, bool strict = true, typename U>               \
  auto ns##Cast(U value)                                              \
      ->std::enable_if_t<                                             \
          std::is_convertible_v<U, std::string> || std::is_enum_v<U>, \
          decltype(detail::enum_cast::ns ::get##fallback<T>())> {     \
    using namespace detail::enum_cast::ns;                            \
    static const auto fb = get##fallback<T>();

#define FUZZUF_ENUM_CAST_END \
  return fb;                 \
  }

#define FUZZUF_ENUM_CAST_CONVERT(name)                                        \
  if constexpr (std::is_convertible_v<U, std::string> || has_##name##_v<U>) { \
    if (get##name<U>() == static_cast<decltype(get##name<U>())>(value)) {     \
      if constexpr (std::is_same_v<fuzzuf::utils::type_traits::RemoveCvrT<T>, \
                                   std::string> ||                            \
                    has_##name##_v<T>) {                                      \
        return get##name<T>();                                                \
      } else if constexpr (strict) {                                          \
        static_assert(!strict,                                                \
                      "enumCast is rejected due to lack of "                  \
                      "correspondig value for " #name);                       \
      }                                                                       \
    }                                                                         \
  }

#endif
