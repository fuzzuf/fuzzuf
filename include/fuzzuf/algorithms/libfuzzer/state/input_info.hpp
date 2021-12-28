/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_INPUT_INFO_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_STATE_INPUT_INFO_HPP
#include "fuzzuf/algorithms/libfuzzer/state/testcase_id.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/void_t.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class InputInfo
 * @brief 入力値をexecutorに渡して実行した結果得られる情報
 * これらの値はexecutorで再度実行する事で取り戻せるため永続化対象には含まれない
 * libFuzzerの実行結果が持つ全ての変数を持ってきてあるが、libFuzzerのいくつかの機能は移植していない(or
 * できない)ため、全く変化しないメンバも存在する
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerCorpus.h#L28
 */
struct InputInfo {
  InputInfo() : id(0), enabled(false), time_of_unit(0) {}
  InputInfo(testcase_id_t id_) : id(id_), enabled(true), time_of_unit(0) {}
  /**
   * @fn
   * この実行結果のenergyを求める
   */
  void updateEnergy(std::size_t global_number_of_features,
                    bool scale_per_exec_time,
                    std::chrono::microseconds average_unit_execution_time);
  /**
   * @fn
   * 指定したfeatureをこの実行結果のfeature_freqsから削除する
   * @param index feature
   */
  bool delete_feature_freq(std::uint32_t index);
  /**
   * @fn
   * 有効な実行結果を持っている場合trueを返す
   */
  operator bool() const { return enabled; }
  /**
   * @fn
   * 指定したfeatureをこの実行結果のfeature_freqsに追加する
   * @param index feature
   */
  void updateFeatureFrequency(std::uint32_t index);

  // 以下libFuzzer由来の要素
  // ExecInputSetから対応する入力を見つけるためのID
  testcase_id_t id;
  bool enabled;
  // 実行時間
  std::chrono::microseconds time_of_unit;
  // 見つかったfeatureの数
  std::size_t features_count = 0u;
  // mutationを行った回数
  std::size_t executed_mutations_count = 0u;
  // ?
  bool never_reduce = false;
  // ?
  bool may_delete_file = false;
  // focus_functionを使っている
  bool has_focus_function = false;
  // 既に存在した同じ入力値の実行結果を置き換えた
  bool reduced = false;
  // energyの値を再計算する必要がある
  bool needs_energy_update = false;
  // この実行結果の重要度 rare_featuresを使って求める
  double energy = 0.0;
  // ?
  double sum_incidence = 0.0;
  // 重複を排したfeatureの値の列
  std::vector<std::uint64_t> unique_feature_set;
  // ?
  std::vector<std::pair<std::uint32_t, std::uint16_t>> feature_freqs;

  // 以下fuzzuf由来の要素
  // 子プロセスの実行結果
  PUTExitReasonType status = PUTExitReasonType::FAULT_NONE;
  // 子プロセスを終了させたシグナル
  unsigned int signal = 0;
  // この入力の重み
  double weight = 0.0;

  // 新しいfeatureを発見した
  std::size_t found_unique_features = 0u;

  // corpusに追加された
  bool added_to_corpus = false;

  // 入力値のハッシュ
  std::string sha1;
  // 入力値の名前
  std::string name;
  // 入力値の長さ
  std::size_t input_size = 0u;
};

/**
 * @class is_input_info
 * @brief 与えられた型TがInputInfo型の要件を満たす場合にtrueを返すメタ関数
 *
 * @tparm T 任意の型
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
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().enabled)>,
                       bool> &&
        std::is_void_v<utils::void_t<decltype(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::declval<utils::type_traits::RemoveCvrT<decltype(
                    std::declval<T &>().time_of_unit)>>()))>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().features_count)>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().executed_mutations_count)>> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().never_reduce)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().may_delete_file)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().has_focus_function)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().reduced)>,
                       bool> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().needs_energy_update)>,
                       bool> &&
        std::is_floating_point_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().energy)>> &&
        std::is_floating_point_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().sum_incidence)>> &&
        std::is_integral_v<
            utils::range::RangeValueT<utils::type_traits::RemoveCvrT<decltype(
                std::declval<T &>().unique_feature_set)>>> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().status)>,
                       PUTExitReasonType> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().signal)>> &&
        std::is_floating_point_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().weight)>> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().found_unique_features)>> &&
        std::is_same_v<utils::type_traits::RemoveCvrT<decltype(
                           std::declval<T &>().added_to_corpus)>,
                       bool> &&
        std::is_same_v<
            utils::type_traits::RemoveCvrT<decltype(std::declval<T &>().sha1)>,
            std::string> &&
        std::is_integral_v<utils::type_traits::RemoveCvrT<decltype(
            std::declval<T &>().input_size)>> &&
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
template <typename T> constexpr bool is_input_info_v = is_input_info<T>::value;

/**
 * @fn
 * InputInfoを文字列に変換する
 * @param dest 出力先
 * @param value 値
 * @param index_count インデントの深さ
 * @param indent インデントに使う文字列
 */
auto toString(std::string &dest, const InputInfo &value,
              std::size_t indent_count, const std::string &indent) -> bool;

} // namespace fuzzuf::algorithm::libfuzzer

#endif
