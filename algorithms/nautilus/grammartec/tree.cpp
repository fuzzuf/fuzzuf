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
 * @file tree.cpp
 * @brief Tree for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <iostream>
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

/**
 * @fn
 * @brief Calculate subtree sizes and parents
 * @param (ctx) Context
 */
void Tree::CalcSubTreeSizesAndParents(Context& ctx) {
  CalcParents(ctx);
  CalcSizes();
}

/**
 * @fn
 * @brief Calculate parents
 * @param (ctx) Context
 */
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

/**
 * @fn
 * @brief Calculate sizes
 */
void Tree::CalcSizes() {
  for (size_t& size: _sizes)
    size = 1;

  for (size_t i = Size() - 1; i > 0; i--)
    _sizes[static_cast<size_t>(_paren[i])] += _sizes[i];
}

/**
 * @fn
 * @brief Get rule ID by node ID
 * @param (n) Node ID
 * @return Rule ID
 */
RuleID Tree::GetRuleID(NodeID n) {
  return _rules[static_cast<size_t>(n)].ID();
}

/**
 * @fn
 * @brief Get the number of current rules
 * @return Number of rules
 */
size_t Tree::Size() {
  return _rules.size();
}

/**
 * @fn
 * @brief Copy this tree
 * @return New tree copied from current tree
 */
Tree Tree::ToTree(Context&) { // Context is unused in Tree impl
  return Tree(_rules, _sizes, _paren);
}

/**
 * @fn
 * @brief Get rule by node ID
 * @param (n) Node ID
 * @param (ctx) Context
 * @return Rule corresponding to node ID
 */
Rule& Tree::GetRule(NodeID n, Context& ctx) {
  return ctx.GetRule(GetRuleID(n));
}

/**
 * @fn
 * @brief Get custom rule data by node ID
 * @param (n) Node ID
 * @return Data of rule (throws exception if rule is not Custom)
 */
std::string Tree::GetCustomRuleData(NodeID n) {
  return _rules[static_cast<size_t>(n)].Data();
}

/**
 * @fn
 * @brief Get rule ID or custom by node ID
 * @param (n) Node ID
 * @return RuleIDOrCustom corresponding to node ID
 */
RuleIDOrCustom& Tree::GetRuleOrCustom(NodeID n) {
  return _rules[static_cast<size_t>(n)];
}

/**
 * @fn
 * @brief Remove every rule
 */
void Tree::Truncate() {
  _rules.clear();
  _sizes.clear();
  _paren.clear();
}

/**
 * @fn
 * @brief Generate tree from nonterminal
 * @param (start) Nonterminal symbol ID
 * @param (len) Maximum length for getting random rule for `start`
 * @param (ctx) Context
 */
void Tree::GenerateFromNT(NTermID start, size_t len, Context& ctx) {
  RuleID rid = ctx.GetRandomRuleForNT(start, len);
  GenerateFromRule(rid, len - 1, ctx);
}

/**
 * @fn
 * @brief Generate tree from rule
 * @param (ruleid) Rule ID
 * @param (max_len) Maximum length
 * @param (ctx) Context
 */
void Tree::GenerateFromRule(RuleID ruleid, size_t max_len, Context& ctx) {
  if (std::holds_alternative<PlainRule>(ctx.GetRule(ruleid).value())) {

    /* PlainRule or ScriptRule */
    Truncate();
    _rules.push_back(RuleIDOrCustom(ruleid));
    _sizes.push_back(0);
    _paren.push_back(NodeID(0));
    ctx.GetRule(ruleid).Generate(*this, ctx, max_len);
    
    _sizes[0] = _rules.size(); // TODO: Check if this is always 1

  } else {

    // NOTE: RegExpRule should work differently here
    throw exceptions::not_implemented(
      "Only PlainRule is supported", __FILE__, __LINE__
    );

  }
}


/**
 * @fn
 * @brief Get nonterminal ID by NodeID
 * @param (n) NodeID
 * @param (ctx) Context
 * @return Nonterminal symbol ID
 */
NTermID TreeLike::GetNontermID(NodeID n, Context& ctx) {
  return GetRule(n, ctx).Nonterm();
}

/**
 * @fn
 * @brief Unparse tree into grammar string
 * @param (id) Node ID
 * @param (ctx) Context
 * @param (data) Reference to string to store result
 */
void TreeLike::Unparse(NodeID id, Context& ctx, std::string& data) {
  Unparser(id, data, *this, ctx).Unparse();
}

/**
 * @fn
 * @brief Convert tree into grammar string
 * @param (ctx) Context
 * @param (data) Reference to string to store result
 */
void TreeLike::UnparseTo(Context& ctx, std::string& data) {
  Unparse(NodeID(0), ctx, data);
}

std::string TreeLike::UnparseNodeToVec(NodeID n, Context& ctx) {
  std::string data;
  Unparse(n, ctx, data);
  return data;
}

std::string TreeLike::UnparseToVec(Context& ctx) {
  return UnparseNodeToVec(NodeID(0), ctx);
}


/**
 * @fn
 * @brief Construct Unparser
 * @param (nid) Node ID
 * @param (w) Data
 * @param (tree) Tree
 * @param (ctx) Context
 */
Unparser::Unparser(NodeID nid, std::string& w, TreeLike& tree, Context& ctx)
  : _tree(tree), _w(w), _ctx(ctx) {
  _i = static_cast<size_t>(nid);
  _stack = {UnparseStep(tree.GetRule(NodeID(_i), ctx).Nonterm())};
  _buffers.clear();
}

/**
 * @fn
 * @brief Forward one step for unparse
 * @return True if successful
 */
bool Unparser::UnparseOneStep() {
  if (_stack.size() == 0)
    return false;

  auto data = _stack.back().value();
  _stack.pop_back();

  if (std::holds_alternative<Term>(data)) {
    // Terminal symbol
    Write(std::get<Term>(data));

  } else if (std::holds_alternative<NTerm>(data)) {
    // Nonterminal symbol
    Nonterm(std::get<NTerm>(data));

  } else {
    throw exceptions::unreachable(
      "Unexpected stack top", __FILE__, __LINE__
    );
  }

  return true;
}

/**
 * @fn
 * @brief Operation for terminal symbols
 * @param (data) Term
 */
void Unparser::Write(std::string& data) {
  if (_buffers.size() > 0) {
    _buffers.back() << data;
  } else {
    _w += data;
  }
}

/**
 * @fn
 * @brief Operation for nonterminal symbols
 * @param (nt) Nonterminal
 */
void Unparser::Nonterm(NTermID nt) {
  NextRule(nt);
}

/**
 * @fn
 * @brief Operation for nonterminal symbols
 * @param (nt) Nonterminal
 */
void Unparser::NextRule(NTermID nt) {
  NodeID nid(_i);
  Rule& rule = _tree.GetRule(nid, _ctx);
  assert(nt == rule.Nonterm());

  _i++;

  if (std::holds_alternative<PlainRule>(rule.value())) {
    // Operation for plain rules
    NextPlain(std::get<PlainRule>(rule.value()));

  } else {

    throw exceptions::not_implemented(
      "Only PlainRule is supported", __FILE__, __LINE__
    );

  }
}

/**
 * @fn
 * @brief Operation for plain rules
 * @param (r) Plain rule
 */
void Unparser::NextPlain(PlainRule r) {
  for (auto it = r.children.rbegin(); it != r.children.rend(); it++) {
    RuleChild rule_child = *it;

    UnparseStep op;
    if (std::holds_alternative<Term>(rule_child.value())) {
      // Push as terminal
      op = UnparseStep(std::get<Term>(rule_child.value()));

    } else if (std::holds_alternative<NTerm>(rule_child.value())) {
      // Push as tonterminal
      op = UnparseStep(std::get<NTerm>(rule_child.value()));

    } else {
      throw exceptions::unreachable(
        "Unexpected RuleChild type", __FILE__, __LINE__
      );
    }

    _stack.push_back(op);

  }
}

/**
 * @fn
 * @brief Unparse all rules
 * @return Node ID (step count)
 */
NodeID Unparser::Unparse() {
  // Unparse while stack is not empty
  while (UnparseOneStep());

  return NodeID(_i);
}

} // namespace fuzzuf::algorithms::nautilus::grammartec;
