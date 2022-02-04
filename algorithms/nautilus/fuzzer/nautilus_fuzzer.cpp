/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file nautilus_fuzzer.cpp
 * @brief Fuzzing loop of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/nautilus_fuzzer.hpp"


namespace fuzzuf::algorithm::nautilus {

Nautilus::Nautilus(std::unique_ptr<NautilusState>&& state_ref)
  : state(std::move(state_ref)) {
  
}

Nautilus::~Nautilus() {
}

} // namespace fuzzuf::algorithm::nautilus
