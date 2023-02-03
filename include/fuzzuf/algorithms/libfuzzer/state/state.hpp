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
 * @file state.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_STATE_HPP
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/config.hpp"
#include "fuzzuf/algorithms/libfuzzer/state/random_traits.hpp"
#include "fuzzuf/algorithms/libfuzzer/utils.hpp"
#include "fuzzuf/algorithms/libfuzzer/version.hpp"
#include "fuzzuf/utils/to_string.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class State
 * @brief Struct to hold libFuzzer state
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L154
 *
 */
struct State {
  State(const State &) = delete;
  State &operator=(const State &) = delete;

  using corpus_distribution_t = std::piecewise_constant_distribution<double>;

  State(std::uint32_t feature_set_size = 1u << 21)
      : global_feature_freqs(feature_set_size, 0u),
        input_sizes_per_feature(feature_set_size, 0u),
        smallest_element_per_feature(feature_set_size, 0u) {}

  // Config to alter libFuzzer behaviour
  FuzzerCreateInfo create_info;
  // Current probability of choosing each input value
  corpus_distribution_t corpus_distribution;
  // If true, corpus_distribution need to be recalculated.
  bool distribution_needs_update = true;

  // List of seldomly detected features.
  // In entropic mode, common features are ignored and never affect on the
  // energy.
  std::vector<std::uint32_t> rare_features;

  // Features listed in the rare features but detected number is larger than the
  // value will be dropped from rare features.
  std::uint16_t freq_of_most_abundant_rare_feature = 0u;
  std::vector<std::uint16_t> global_feature_freqs;
  std::size_t executed_mutations_count = 0u;
  // 追加されたfeatureの数
  std::size_t added_features_count = 0u;
  // 更新されたfeatureの数
  std::size_t updated_features_count = 0u;
  std::vector<std::uint32_t> input_sizes_per_feature;
  std::vector<std::uint32_t> smallest_element_per_feature;
};

auto toString(std::string &dest, const State &value, std::size_t indent_count,
              const std::string &indent) -> bool;

/**
 * @class IsState
 * @brief Meta function to check if the type satisfies State concept
 *
 * @tparam T Type to check
 */
template <typename T, typename Enable = void>
struct IsState : public std::false_type {};
template <typename T>
struct IsState<
    T,
    std::enable_if_t<
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().create_info)>,
                       FuzzerCreateInfo> &&
        is_std_distribution_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().corpus_distribution)>> &&
        std::is_convertible_v<
            utils::type_traits::RemoveCvrT<
                decltype(std::declval<T &>().distribution_needs_update)>,
            bool> &&
        std::is_integral_v<
            utils::range::RangeValueT<utils::type_traits::RemoveCvrT<
                decltype(std::declval<T &>().rare_features)>>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>()
                         .freq_of_most_abundant_rare_feature)>> &&
        std::is_integral_v<
            utils::range::RangeValueT<utils::type_traits::RemoveCvrT<
                decltype(std::declval<T &>().global_feature_freqs)>>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().executed_mutations_count)>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().added_features_count)>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().updated_features_count)>> &&
        std::is_integral_v<
            utils::range::RangeValueT<utils::type_traits::RemoveCvrT<
                decltype(std::declval<T &>().input_sizes_per_feature)>>> &&
        std::is_integral_v<
            utils::range::RangeValueT<utils::type_traits::RemoveCvrT<
                decltype(std::declval<T &>().smallest_element_per_feature)>>>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_state_v = IsState<T>::value;

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
