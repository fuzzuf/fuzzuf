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
 * @file option.hpp
 * @brief Option of nautilus
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_OPTIONS_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_OPTION_HPP

namespace fuzzuf::algorithm::nautilus::fuzzer::option {

struct NautilusTag {};

/* Default configuration */
constexpr uint8_t GetDefaultNumOfThreads() { return 1; }
constexpr size_t GetDefaultThreadSize() { return 4194304; }
constexpr uint16_t GetDefaultNumOfGenInputs() { return 100; }
constexpr size_t GetDefaultNumOfDetMuts() { return 1; }
constexpr size_t GetDefaultMaxTreeSize() { return 1000; }
constexpr size_t GetDefaultBitmapSize() { return 1 << 16; }

}  // namespace fuzzuf::algorithm::nautilus::fuzzer::option

#endif
