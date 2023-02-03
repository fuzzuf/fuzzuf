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
 * @file mutation.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_MUTATION_HPP
#include "fuzzuf/algorithms/libfuzzer/mutation/change_ascii_integer.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/change_binary_integer.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/change_bit.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/change_byte.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/copy_part.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/crossover.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/dictionary.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/erase_bytes.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/increment_mutation_count.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/insert_byte.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/insert_repeated_bytes.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/mask.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/shuffle_bytes.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/to_ascii.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation/utils.hpp"
#endif
