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
#include "fuzzuf/algorithms/libfuzzer/utils.hpp"
#include <boost/spirit/include/karma.hpp>
#include <cstddef>
#include <cstdint>

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @fn
 * log_2を整数にキャストした物を「1になっている最も左側のbitはどれか」を使って雑に求める
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerUtil.h#L93
 */
auto lflog(std::size_t x) -> std::size_t {
  return sizeof(x) * 8u - __builtin_clzll(x) - 1U;
}

} // namespace fuzzuf::algorithm::libfuzzer
