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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_STATE_HPP
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include <boost/functional/hash.hpp>
#include <unordered_set>

namespace fuzzuf::algorithm::nezha {

/**
 * @class output_equal_to
 * @brief 2つのrangeが等しい事を確認するcallable object
 */
struct output_equal_to {
  /**
   * @fn
   * 2つのrangeが等しい事を確認する
   * @tparm R1 1つめのrangeの型
   * @tparm R2 2つめのrangeの型
   * @param r1 1つめのrange
   * @param r2 2つめのrange
   * @return 等しい場合はtrueを返す。そうでない場合はfalseを返す。
   */
  template <typename R1, typename R2>
  bool operator()(const R1 &r1, const R2 &r2) const {
    return std::equal(r1.begin(), r1.end(), r2.begin(), r2.end());
  }
};

/**
 * @class output_hash
 * @brief vectorのhashを求めるcallable object
 */
struct output_hash {
  /**
   * @fn
   * vectorのhashを求める
   * 実装はBoost.Hashそのまま
   * @tparm R1 rangeの型
   * @param r1 range
   * @return ハッシュ値を返す
   */
  template <typename R1> std::size_t operator()(const R1 &r1) const {
    return boost::hash<R1>()(r1);
  }
};

// 各ターゲットでの実行結果がcorpusに追加されたかどうかを記録するvector
using trace_t = std::vector<bool>;
// trace_t型の値が既知の物かどうか判断するためのset
using known_traces_t =
    std::unordered_set<trace_t, output_hash, output_equal_to>;

// 各ターゲットでの終了理由を記録するvector
using status_t = std::vector<PUTExitReasonType>;
// status_t型の値が既知の物かどうかを判断するためのset
using known_status_t =
    std::unordered_set<status_t, output_hash, output_equal_to>;

// 各ターゲットの標準出力のハッシュを記録するvector
using outputs_t = std::vector<std::size_t>;
// outputs_t型の値が既知の物かどうかを判断するためのset
using known_outputs_t =
    std::unordered_set<outputs_t, output_hash, output_equal_to>;

} // namespace fuzzuf::algorithm::nezha

#endif
