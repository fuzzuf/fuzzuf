/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
 * 
S * This program is free software: you can redistribute it and/or modify
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
 * @file tree.cpp
 * @brief Tree for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/exceptions.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

/**
 * @fn
 * @brief Construct tree from rule vector
 * @param (rules) Vector of rules
 * @param (ctx) Context
 */
Tree::Tree(std::vector<RuleIDOrCustom> rules, Context& ctx)
  : _rules(rules) {
  _sizes.reserve(_rules.size());
  _paren.reserve(_rules.size());
  std::fill(_sizes.begin(), _sizes.end(), 0);
  std::fill(_paren.begin(), _paren.end(), NodeID(0));

  if (_rules.size() > 0)
    CalcSubTreeSizesAndParents(ctx);
}

void Tree::CalcSubTreeSizesAndParents(Context& ctx) {
  CalcParents(ctx);
  CalcSizes();
}

void Tree::CalcParents(Context& ctx) {
  if (Size() == 0)
    return;

  std::vector<std::pair<NTermID, NodeID>> stack;
  stack.push_back(
    std::pair<NTermID, NodeID>(GetRule(NodeID(0), ctx).Nonterm(), NodeID(0))
  );

  for (size_t i = 0; i < Size(); i++) {
    NodeID node_id(i);
    NTermID nonterm = GetRule(node_id, ctx).Nonterm();

    if (stack.size() == 0)
      throw exceptions::fuzzuf_runtime_error(
        "Not a valid tree for unparsing!", __FILE__, __LINE__
      );

    auto [nterm_id, node] = stack[stack.size() - 1];
    stack.pop_back();
    if (nterm_id != nonterm)
      throw exceptions::fuzzuf_runtime_error(
        "Not a valid tree for unparsing!", __FILE__, __LINE__
      );

    _paren[i] = node;

    Rule rule = GetRule(node_id, ctx);
    std::vector<NTermID> nonterms = rule.Nonterms();
    for (auto it = nonterms.rbegin(); it != nonterms.rend(); ++it) {
      stack.push_back(std::pair<NTermID, NodeID>(*it, node_id));
    }
  }
}

void Tree::CalcSizes() {
  for (size_t& size: _sizes)
    size = 1;

  for (size_t i = Size(); i > 0; i--)
    _sizes[static_cast<size_t>(_paren[i])] += _sizes[i];
}

RuleID Tree::GetRuleID(NodeID n) {
  return _rules[static_cast<size_t>(n)].ID();
}

size_t Tree::Size() {
  return _rules.size();
}

Tree Tree::ToTree(Context&) {
  return Tree(_rules, _sizes, _paren);
}

Rule& Tree::GetRule(NodeID n, Context& ctx) {
  return ctx.GetRule(GetRuleID(n));
}

std::string Tree::GetCustomRuleData(NodeID n) {
  return _rules[static_cast<size_t>(n)].Data();
}

RuleIDOrCustom& Tree::GetRuleOrCustom(NodeID n) {
  return _rules[static_cast<size_t>(n)];
}

void Tree::Truncate() {
  _rules.clear();
  _sizes.clear();
  _paren.clear();
}

void Tree::GenerateFromNT(NTermID start, size_t len, Context& ctx) {
  RuleID rid = ctx.GetRandomRuleForNT(start, len);
  GenerateFromRule(rid, len - 1, ctx);
}

void Tree::GenerateFromRule(RuleID ruleid, size_t max_len, Context& ctx) {
  // TODO: Is this branch necessary?
  if (std::holds_alternative<RegExpRule>(ctx.GetRule(ruleid).value())) {

    /* RegExpRule */
    RuleIDOrCustom rid(ruleid, "[FIXME] what's this");
    Truncate();
    _rules.push_back(rid);
    _sizes.push_back(0);
    _paren.push_back(NodeID(0));
    _sizes[0] = _rules.size(); // TODO: Check if this is always 1

  } else {

    /* PlainRule or ScriptRule */
    Truncate();
    _rules.push_back(RuleIDOrCustom(ruleid));
    _sizes.push_back(0);
    _paren.push_back(NodeID(0));
    ctx.GetRule(ruleid).Generate(*this, ctx, max_len);
    _sizes[0] = _rules.size(); // TODO: Check if this is always 1

  }
}

} // namespace fuzzuf::algorithms::nautilus::grammartec;
