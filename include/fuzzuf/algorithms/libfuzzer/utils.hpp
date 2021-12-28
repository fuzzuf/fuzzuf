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
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_UTILS_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_UTILS_HPP
#include "fuzzuf/utils/to_string.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include <cstddef>
#include <vector>
namespace fuzzuf::algorithm::libfuzzer {

/**
 * @fn
 * log_2を整数にキャストした物を「1になっている最も左側のbitはどれか」を使って雑に求める
 * libFuzzerの対応箇所
 * https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/lib/fuzzer/FuzzerUtil.h#L93
 */
auto lflog(std::size_t x) -> std::size_t;

#define FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(name)                          \
  {                                                                            \
    utils::make_indent(dest, indent_count, indent);                            \
    dest += #name;                                                             \
    dest += " : ";                                                             \
    if (!utils::toStringADL(dest, value.name))                                 \
      return false;                                                            \
    dest += "\n";                                                              \
  }

} // namespace fuzzuf::algorithm::libfuzzer
#endif
