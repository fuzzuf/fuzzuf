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
#ifndef FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_GATHER_OUTPUT_HPP
#define FUZZUF_INCLUDE_ALGORITHM_NEZHA_EXECUTOR_GATHER_OUTPUT_HPP
#include "fuzzuf/utils/range_traits.hpp"
#include <type_traits>

namespace fuzzuf::algorithm::nezha::executor {

/**
 * @fn
 * ターゲットを実行して得られた標準出力のハッシュをoutput_diffに追加する
 *
 * @tparm InputInfo 実行結果の型
 * @tparm OutputDiff output_diffの型
 * @param exec_result 実行結果
 * @param output_diff std::size_t型を要素とするappendableなコンテナ
 */
template <typename Range, typename OutputDiff>
auto GatherOutput(const Range &output, OutputDiff &output_diff)
    -> std::enable_if_t<
        std::is_same_v<utils::range::RangeValueT<OutputDiff>, std::size_t>> {
  utils::range::append(output_hash()(output), output_diff);
}

} // namespace fuzzuf::algorithm::nezha::executor

#endif
