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
 * @file input_info.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_INPUT_INFO_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_INPUT_INFO_HPP
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "fuzzuf/algorithms/libfuzzer/state/testcase_id.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/void_t.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class InputInfo
 * @brief execution result
 * This class contains values retrived from executor and scratch values to
 * calculate weight All values in Input Info of original implementation has been
 * ported, yet some of them are not used due to some functionalities are not
 * ported.
 *
 * Corresponding code of original libFuzzer implementation
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L28
 */
struct InputInfo {
  InputInfo() : id(0), enabled(false), time_of_unit(0) {}
  InputInfo(testcase_id_t id_) : id(id_), enabled(true), time_of_unit(0) {}
  /**
   * Calculate energy of this execution result
   */
  void updateEnergy(std::size_t global_number_of_features,
                    bool scale_per_exec_time,
                    std::chrono::microseconds average_unit_execution_time);
  /**
   * Remove specified feature from feature_freqs of this execution result.
   * @param index Feature id
   */
  bool delete_feature_freq(std::uint32_t index);
  /**
   * Return true if the InputInfo contains active execution result.
   */
  operator bool() const { return enabled; }
  /**
   * Append specified feature to feature_freqs of this execution result.
   * @param index Feature id
   */
  void updateFeatureFrequency(std::uint32_t index);

  /// ID to bind an input value in ExecInputSet to this execution result.
  testcase_id_t id;
  /// If true, the InputInfo contains active execution result.
  bool enabled;
  /// Values ported from original implementation
  /// elapsed time of execution
  std::chrono::microseconds time_of_unit;
  /// detected feature count
  std::size_t features_count = 0u;
  /// applied mutation count
  std::size_t executed_mutations_count = 0u;
  // ?
  bool never_reduce = false;
  // ?
  bool may_delete_file = false;
  /// the input value is generated using focus function
  bool has_focus_function = false;
  /// this execution result replaced existing one
  bool reduced = false;
  /// If true, since values affecting to the energy has changed, energy need to
  /// be recalculated.
  bool needs_energy_update = false;
  /**
   * Importance of this execution result.
   * rare_features affects on this value.
   */
  double energy = 0.0;
  // ?
  double sum_incidence = 0.0;
  // unique feature ids detected on this execution
  std::vector<std::uint64_t> unique_feature_set;
  // ?
  std::vector<std::pair<std::uint32_t, std::uint16_t>> feature_freqs;

  /**
   * fuzzuf specific variables
   * status code of the target execution
   */
  feedback::PUTExitReasonType status = feedback::PUTExitReasonType::FAULT_NONE;
  /// signal number that caused the target to terminate
  unsigned int signal = 0;
  /// weight of this execution result
  double weight = 0.0;

  /// number of novel features by this execution
  std::size_t found_unique_features = 0u;

  /// If true, the execution result has added to corpus
  bool added_to_corpus = false;

  /// Hash value of the input value.
  std::string sha1;
  /**
   * Name of the input value
   * If the input value has name and requested to make persistent, the name is
   * used as the filename. If the input value doesn't have name but requested to
   * make persistent, the sha1 is used as the filename.
   */
  std::string name;
  /// The length of input value.
  std::size_t input_size = 0u;
};

/**
 * @class is_input_info
 * @brief Meta function to check if the type satisfies InputInfo concept
 *
 * @tparam T Type to check
 */
template <typename T, typename Enable = void>
struct is_input_info : public std::false_type {};
template <typename T>
struct is_input_info<
    T,
    std::enable_if_t<
        std::is_same_v<
            utils::type_traits::RemoveCvrT<decltype(std::declval<T &>().id)>,
            testcase_id_t> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().enabled)>,
                       bool> &&
        std::is_void_v<utils::void_t<
            decltype(std::chrono::duration_cast<std::chrono::microseconds>(
                std::declval<utils::type_traits::RemoveCvrT<
                    decltype(std::declval<T &>().time_of_unit)>>()))>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().features_count)>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().executed_mutations_count)>> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().never_reduce)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().may_delete_file)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().has_focus_function)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().reduced)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().needs_energy_update)>,
                       bool> &&
        std::is_floating_point_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().energy)>> &&
        std::is_floating_point_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().sum_incidence)>> &&
        std::is_integral_v<
            utils::range::RangeValueT<utils::type_traits::RemoveCvrT<
                decltype(std::declval<T &>().unique_feature_set)>>> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().status)>,
                       feedback::PUTExitReasonType> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().signal)>> &&
        std::is_floating_point_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().weight)>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().found_unique_features)>> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<
                           decltype(std::declval<T &>().added_to_corpus)>,
                       bool> &&
        std::is_same_v<
            utils::type_traits::RemoveCvrT<decltype(std::declval<T &>().sha1)>,
            std::string> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<
            decltype(std::declval<T &>().input_size)>> &&
        std::is_void_v<utils::void_t<decltype(std::declval<T &>().updateEnergy(
            std::declval<std::size_t>(), std::declval<bool>(),
            std::declval<std::chrono::microseconds>()))>> &&
        std::is_same_v<decltype(std::declval<T &>().delete_feature_freq(
                           std::declval<std::uint32_t>())),
                       bool> &&
        std::is_void_v<
            utils::void_t<decltype(std::declval<T &>().updateFeatureFrequency(
                std::declval<std::uint32_t>()))>> &&
        std::is_convertible_v<T, bool>>> : public std::true_type {};
template <typename T>
constexpr bool is_input_info_v = is_input_info<T>::value;

/**
 * Serialize InputInfo into string
 * @param dest Serialized string is stored in this value
 * @param value InputInfo to serialize
 * @param index_count Initial indentation depth
 * @param indent String to insert for indentation
 */
auto toString(std::string &dest, const InputInfo &value,
              std::size_t indent_count, const std::string &indent) -> bool;

}  // namespace fuzzuf::algorithm::libfuzzer

#endif
