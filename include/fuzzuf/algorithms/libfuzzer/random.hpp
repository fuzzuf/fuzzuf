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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_RANDOM_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_RANDOM_HPP
#include <cassert>
#include <cctype>
#include <type_traits>
namespace fuzzuf::algorithm::libfuzzer {
namespace detail {

/**
 * @fn
 * min以上max未満の乱数を返す
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerRandom.h#L21
 *
 * @tparm V 任意の整数型
 * @tparm RNG stdの乱数生成器のconceptを満たす乱数生成器の型
 * @param rng 乱数生成器
 * @param min 最小値(含む)
 * @param max 最大値(含まない)
 */
template <typename V, typename RNG>
auto random_value(RNG &rng, V min, V max)
    -> std::enable_if_t<std::is_integral_v<V>, V> {
  assert(min < max);
  if (min == max)
    return 0;
  return min + (rng() % (max - min));
}

} // namespace detail

/**
 * @fn
 * libFuzzer互換乱数分布
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerRandom.h#L28
 *
 * @tparm V 任意の整数型
 * @tparm RNG stdの乱数生成器のconceptを満たす乱数生成器の型
 * @param rng 乱数生成器
 * @param max 最大値(含まない)
 */
template <typename V, typename RNG>
auto random_value(RNG &rng, V max)
    -> std::enable_if_t<std::is_integral_v<V>, V> {
  return max ? (rng() % max) : V(0);
}

/**
 * @fn
 * libFuzzer互換乱数分布
 *
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerRandom.h#L22
 *
 * @tparm V 任意の整数型
 * @tparm RNG stdの乱数生成器のconceptを満たす乱数生成器の型
 * @param rng 乱数生成器
 */
template <typename V, typename RNG>
auto random_value(RNG &rng)
    -> std::enable_if_t<std::is_integral_v<V> && std::is_same_v<bool, V>, V> {
  return detail::random_value(rng, 0, 2);
}

/**
 * @fn
 * libFuzzer互換乱数分布
 * @tparm V 任意の整数型
 * @tparm RNG stdの乱数生成器のconceptを満たす乱数生成器の型
 * @param rng 乱数生成器
 */
template <typename V, typename RNG>
auto random_value(RNG &rng)
    -> std::enable_if_t<std::is_integral_v<V> && !std::is_same_v<bool, V>, V> {
  return detail::random_value(rng, std::numeric_limits<V>::min(),
                              std::numeric_limits<V>::max());
}

} // namespace fuzzuf::algorithm::libfuzzer
#endif
