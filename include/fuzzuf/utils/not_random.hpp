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
 * @file not_random.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_NOT_RANDOM_HPP
#define FUZZUF_INCLUDE_UTILS_NOT_RANDOM_HPP
#include <limits>
#include <type_traits>
namespace fuzzuf::utils::not_random {
// 常に特定の値を返すstd互換乱数生成器
// ユニットテストの結果を予測しやすくする目的で使う
template <typename T, typename Enable = void>
struct fixed {};
template <typename T>
class fixed<T, std::enable_if_t<std::is_integral_v<T> &&  // Tは整数
                                std::is_unsigned_v<T>     // Tは符号なし
                                >> {
 public:
  using result_type = unsigned int;
  fixed() : value(std::numeric_limits<result_type>::min()){};
  fixed(result_type v) : value(v){};
  void seed(result_type v) { value = v; };
  result_type operator()() const { return value; }
  constexpr static result_type min() {
    return std::numeric_limits<result_type>::min();
  }
  constexpr static result_type max() {
    return std::numeric_limits<result_type>::max();
  }

 private:
  T value;
};
// 特定の値を初期値として取り出す度にインクリメントした値を返すstd互換乱数生成器
// ユニットテストの結果を予測しやすくする目的で使う
template <typename T, typename Enable = void>
struct Sequential {};
template <typename T>
class Sequential<T, std::enable_if_t<std::is_integral_v<T> &&  // Tは整数
                                     std::is_unsigned_v<T>  // Tは符号なし
                                     >> {
 public:
  using result_type = unsigned int;
  Sequential() : value(std::numeric_limits<result_type>::min()){};
  Sequential(result_type v) : value(v){};
  void seed(result_type v) { value = v; };
  result_type operator()() { return value++; }
  constexpr static result_type min() {
    return std::numeric_limits<result_type>::min();
  }
  constexpr static result_type max() {
    return std::numeric_limits<result_type>::max();
  }

 private:
  T value;
};

}  // namespace fuzzuf::utils::not_random
#endif
