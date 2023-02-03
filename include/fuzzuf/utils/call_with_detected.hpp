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
 * @file call_with_detected.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_CALL_WITH_DETECTED_HPP
#define FUZZUF_INCLUDE_UTILS_CALL_WITH_DETECTED_HPP

#include <type_traits>

#include "fuzzuf/utils/type_traits/remove_cvr.hpp"

namespace fuzzuf::utils {

template <template <typename> typename T, typename F>
void callWithDetected(F &&) {}

template <template <typename> typename T, typename F, typename Head,
          typename... Tail>
auto callWithDetected(F &&func, Head &&head, Tail &&...tail)
    -> std::enable_if_t<T<Head>::value> {
  func(std::forward<Head>(head));
  callWithDetected<T>(std::forward<F>(func), std::forward<Tail>(tail)...);
}
template <template <typename> typename T, typename F, typename Head,
          typename... Tail>
auto callWithDetected(F &&func, Head &&, Tail &&...tail)
    -> std::enable_if_t<!T<Head>::value> {
  callWithDetected<T>(std::forward<F>(func), std::forward<Tail>(tail)...);
}

}  // namespace fuzzuf::utils

#endif
