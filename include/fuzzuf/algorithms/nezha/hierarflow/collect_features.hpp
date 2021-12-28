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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_COLLECT_FEATURES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_HIERARFLOW_COLLECT_FEATURES_HPP
#include "fuzzuf/algorithms/nezha/executor/collect_features.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"

namespace fuzzuf::algorithm::nezha {
/**
 * @class CollectFeatures
 * @brief ターゲットの実行結果をもとにfeaturesを求める
 * featureとは実行結果の際立った特徴にユニークなIDを与えたもので、主に未到達edgeに到達した場合がこれに該当する
 * featuresはこの実行結果のfeatureを並べたベクタで、libFuzzerはfeaturesに基づいてその入力がChooseRandomSeedで選ばれる確率を変化させる
 * 計算結果はexec_result_index番目の引数に置かれた実行結果の詳細に書かれる
 * @tparm F このノードを通る引数を定義するための関数型
 * @tparm state_index
 * state_index番目の引数をState型とみなしてそこから計算方法に関わる設定を得る
 * @tparm input_index input_index番目の引数を入力値が入ったrangeと見做す
 * @tparm coverage_index coverage_index番目の引数をedge
 * coverageが入ったrangeと見做す
 * @tparm exec_result_index
 * exec_result_index番目の引数を実行結果の詳細が入ったInputInfo型と見做す
 */
template <typename F, typename Path> struct CollectFeatures {};
template <typename R, typename... Args, typename Path>
struct CollectFeatures<R(Args...), Path>
    : public HierarFlowRoutine<R(Args...), R(Args...)> {
public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * コンストラクタ
   * @param module_offset
   * カバレッジのfeatureのオフセット。あるedgeを通過している事を表すfeatureはカバレッジの先頭からそのedgeまでのバイト数とedgeを通った回数から計算される。ライブラリを動的リンクしている場合や、複数のターゲットの実行結果を扱う場合、異なるカバレッジのfeatureが同じIDにならないように、カバレッジの先頭のedgeを何バイト目のedgeと見做すかを指定する必要がある
   */
  CollectFeatures(std::uint32_t module_offset_ = 0)
      : module_offset(module_offset_) {}
  /**
   * HierarFlowの実行時に呼び出される関数
   * @param args 引数
   * @return グラフの進行方向
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("CollectFeatures", enter)
    Path()(
        [&](auto &&...sorted) {
          executor::CollectFeatures(sorted..., module_offset);
        },
        std::forward<Args>(args)...);
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(CollectFeatures)
  }

private:
  std::uint32_t module_offset;
};
namespace standard_order {
template <typename T>
using CollectFeaturesStdArgOrderT = decltype(
    T::state && T::corpus && T::input && T::exec_result && T::coverage);
template <typename F, typename Ord>
using CollectFeatures =
    nezha::CollectFeatures<F, CollectFeaturesStdArgOrderT<Ord>>;
} // namespace standard_order

} // namespace fuzzuf::algorithm::nezha

#endif
