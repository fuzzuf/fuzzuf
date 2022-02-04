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

#include <string>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

class Tree {
public:
  Tree(std::vector<RuleIDOrCustom> rules, Context &ctx);
  Tree(std::vector<RuleIDOrCustom> rules,
       std::vector<size_t> sizes,
       std::vector<NodeID> paren)
    : _rules(rules), _sizes(sizes), _paren(paren) {};
  std::vector<RuleIDOrCustom>& rules() { return _rules; }
  std::vector<size_t>& sizes() { return _sizes; }
  std::vector<NodeID>& paren() { return _paren; }

  void CalcSubTreeSizesAndParents(Context &ctx);
  void CalcParents(Context &ctx);
  void CalcSizes();

  RuleID GetRuleID(NodeID n);
  size_t Size();
  Tree ToTree(Context& ctx);
  Rule& GetRule(NodeID n, Context& ctx);
  std::string GetCustomRuleData(NodeID n);
  RuleIDOrCustom& GetRuleOrCustom(NodeID n);

  void Truncate();
  void GenerateFromNT(NTermID start, size_t len, Context& ctx);
  void GenerateFromRule(RuleID ruleid, size_t max_len, Context& ctx);

private:
  std::vector<RuleIDOrCustom> _rules;
  std::vector<size_t> _sizes;
  std::vector<NodeID> _paren;
};

} // namespace fuzzuf::algorithms::nautilus::grammartec
