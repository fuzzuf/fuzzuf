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
 * @file die_fuzzer.cpp
 * @brief Fuzzing loop of DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/die/die_fuzzer.hpp"

#include "fuzzuf/algorithms/die/die_hierarflow_routines.hpp"

namespace fuzzuf::algorithm::die {

using namespace fuzzuf::algorithm::die;

/**
 * @fn
 * @brief Build HierarFlow of DIE
 */
void DIEFuzzer::BuildFuzzFlow() {
  using namespace fuzzuf::algorithm::afl::routine::other;
  using namespace fuzzuf::algorithm::die::routine::mutation;
  using namespace fuzzuf::algorithm::die::routine::other;
  using namespace fuzzuf::algorithm::die::routine::update;

  using fuzzuf::hierarflow::CreateDummyParent;
  using fuzzuf::hierarflow::CreateNode;

  /* Create head node */
  fuzz_loop = CreateDummyParent<void(void)>();

  /* Create middle nodes (steps done before and after actual mutations) */
  auto select_seed = CreateNode<SelectSeedTemplate<DIEState>>(*state);

  /* Mutation for DIE */
  auto mutate = CreateNode<DIEMutate>(*state);
  auto execute = CreateNode<DIEExecute>(*state);
  auto update = CreateNode<DIEUpdate>(*state);

  fuzz_loop << (select_seed << mutate << execute << update);
}

}  // namespace fuzzuf::algorithm::die
