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
 * @file for_each_multi_index_values.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_FOR_EACH_MULTI_INDEX_VALUES_HPP
#define FUZZUF_INCLUDE_UTILS_FOR_EACH_MULTI_INDEX_VALUES_HPP
#include <boost/multi_index_container.hpp>
namespace fuzzuf::utils {

/**
 * Call specified function for each element of multi index container, in the
 * specified order. In the case the function modifies the values, the order in
 * the container may be changed during the loop, yet the order to apply function
 * are not changed during the loop. This means, even if the values changed, it
 * is guaranteed that all elements in the container are passed to the function
 * just once.
 * @tparam I Type of index of multi index container
 * @tparam F Type of function to apply
 * @tparam If True, function is applied only on valid ( The value casted to bool
 * is true ) elements. Otherwise, function is applied to all elements.
 * @param index Multi value container index to specify order
 * @param func Callback function with one argument that receive reference to the
 * element of container example: forEachMultiIndexValues< true >( corpus.get<
 * Sequential >(), []( InputInfo &v ) { std::cout << v.id << std::endl; } );
 * This displays valid InputInfos in the corpus, in appended order.
 */
template <bool valid_only, typename I, typename F>
void ForEachMultiIndexValues(I &index, F &&func) {
  std::vector<typename I::iterator> iters;
  iters.reserve(index.size());
  for (auto iter = index.begin(); iter != index.end(); ++iter) {
    if constexpr (valid_only) {
      if (bool(*iter)) iters.push_back(iter);
    } else {
      iters.push_back(iter);
    }
  }
  for (auto iter : iters) {
    index.modify(iter, std::forward<F>(func));
  }
}

}  // namespace fuzzuf::utils

#endif
