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
 * @file nautilus_state.hpp
 * @brief Global state used for Nautilus during hieraflow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <memory>
#include "fuzzuf/algorithms/nautilus/fuzzer/setting.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/mutator.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

using namespace fuzzuf::algorithm::nautilus::grammartec;

/* Shared global state */
struct NautilusState {
  explicit NautilusState(
    std::shared_ptr<const NautilusSetting> setting,
    std::shared_ptr<NativeLinuxExecutor> executor
  );

  std::shared_ptr<const NautilusSetting> setting;
  Context ctx;
  //ChunkStore cks;
};

} // namespace fuzzuf::algorithm::nautilus::fuzzer
