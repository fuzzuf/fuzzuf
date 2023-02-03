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
 * @file collect_features.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_COLLECT_FEATURES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_FEATURE_COLLECT_FEATURES_HPP
#include <boost/range/iterator_range.hpp>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

#include "fuzzuf/algorithms/libfuzzer/feature/counter_to_feature.hpp"
#include "fuzzuf/algorithms/libfuzzer/feature/for_each_non_zero_byte.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/void_t.hpp"
namespace fuzzuf::algorithm::libfuzzer::feature {

template <typename Cov, typename Enable = void>
struct CoverageDepth {};
template <typename Cov>
struct CoverageDepth<Cov,
                     std::enable_if_t<utils::range::is_range_of_v<
                         utils::type_traits::RemoveCvrT<Cov>, std::uint8_t>>>
    : public std::integral_constant<unsigned int, 1u> {};
template <typename Cov>
struct CoverageDepth<Cov,
                     std::enable_if_t<!utils::range::is_range_of_v<
                         utils::type_traits::RemoveCvrT<Cov>, std::uint8_t>>>
    : public std::integral_constant<
          unsigned int, CoverageDepth<utils::range::RangeValueT<
                            utils::type_traits::RemoveCvrT<Cov>>>::value +
                            1u> {};

template <typename Cov>
constexpr unsigned int coverage_depth_v = CoverageDepth<Cov>::value;

/**
 * Find features, then call cb for each feature.
 *
 * @tparam State LibFuzzer state object type
 * @tparam Cov Range of std::uint8_t to pass coverage
 * @tparam Callback Callable with one integer argument that indicates ID of
 * detected feature.
 * @param state LibFuzzer state object
 * @param cov Coverage retrived from the executor
 * @param module_offset
 * Consider head of coverage is mode_offset'th element of coverage
 * @param cb Callable with one integer argument that indicates ID of detected
 * feature.
 */
template <typename State, typename Cov, typename Callback>
auto CollectFeatures(State &state, const Cov &cov, std::uint32_t module_offset,
                     Callback cb)
    -> std::enable_if_t<
        is_state_v<State> && coverage_depth_v<Cov> == 1u &&
            std::is_void_v<utils::void_t<decltype(std::declval<Callback>()(
                std::declval<std::uint32_t>()))>>,
        std::size_t> {
  using count_t = std::uint32_t;
  auto handle_8bit_counter = [&](count_t first_feature, count_t index,
                                 std::uint8_t counter) {
    if (state.create_info.config.use_counters)
      cb(first_feature * 8 + index * 8 + CounterToFeature(counter));
    else
      cb(first_feature + index);
  };
  std::size_t first_feature = ForEachNonZeroByte(
      boost::make_iterator_range(cov.data(), std::next(cov.data(), cov.size())),
      module_offset, handle_8bit_counter);
  return first_feature;
}

}  // namespace fuzzuf::algorithm::libfuzzer::feature

#endif
