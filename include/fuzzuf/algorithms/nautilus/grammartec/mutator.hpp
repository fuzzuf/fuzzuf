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
 * @file tree.hpp
 * @brief Tree for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <functional>
#include <optional>
#include <unordered_set>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

using FTester = std::function<bool(
  TreeMutation&,
  std::unordered_set<size_t>&,
  Context&
)>;

class Mutator {
public:
  Mutator(Context& ctx) : _scratchpad(Tree({}, ctx)) {}
  bool MinimizeTree(Tree& tree,
                    std::unordered_set<size_t>& bits,
                    Context& ctx,
                    size_t start_index, size_t end_index,
                    FTester& tester);
  static std::optional<Tree> TestAndConvert(
    Tree& tree_a, NodeID n_a,
    Tree& tree_b, NodeID n_b,
    Context& ctx,
    std::unordered_set<size_t>& fresh_bits,
    FTester& tester
  );

private:
  Tree _scratchpad;
};

} // namespace fuzzuf::algorithms::nautilus::grammartec
