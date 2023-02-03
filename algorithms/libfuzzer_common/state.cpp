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
 * @file state.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/libfuzzer/state/state.hpp"

#include "fuzzuf/algorithms/libfuzzer/utils.hpp"

namespace fuzzuf::algorithm::libfuzzer {

auto toString(std::string &dest, const State &value, std::size_t indent_count,
              const std::string &indent) -> bool {
  utils::make_indent(dest, indent_count, indent);
  dest += "State\n";
  ++indent_count;
  toString(dest, value.create_info, indent_count, "  ");
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(rare_features)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(freq_of_most_abundant_rare_feature)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(global_feature_freqs)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(executed_mutations_count)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(added_features_count)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(updated_features_count)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(input_sizes_per_feature)
  FUZZUF_ALGORITHMS_LIBFUZZER_DUMP_MEMBER(smallest_element_per_feature)
  return true;
}

}  // namespace fuzzuf::algorithm::libfuzzer
