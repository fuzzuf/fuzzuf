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
 * @file tree.cpp
 * @brief Tree for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 *
 * @details This file defines the tree and its operations.
 *          There are two types of trees: Tree and TreeMutation,
 *          and both inherits theTreeLike class.
 */
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"

#include <unordered_set>

#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

/**
 * @fn
 * Construct a tree from a vector of rules.
 * @brief Construct a Tree instance
 * @param (rules) Vector of rules
 * @param (ctx) Context
 */
Tree::Tree(std::vector<RuleIDOrCustom>&& rules, Context& ctx)
    : _rules(std::move(rules)) {
  /* resize: Not only allocate buffer but also change size */
  _sizes.resize(_rules.size(), 0);
  _paren.resize(_rules.size(), NodeID(0));

  if (_rules.size() > 0) CalcSubTreeSizesAndParents(ctx);
}

/**
 * @fn
 * Calculate the sizes for each subtree and parent.
 * @brief Calculate size information
 * @param (ctx) Context
 */
void Tree::CalcSubTreeSizesAndParents(Context& ctx) {
  CalcParents(ctx);
  CalcSizes();
}

/**
 * @fn
 * Calculate parent information.
 * @brief Calculate parents
 * @param (ctx) Context
 */
void Tree::CalcParents(Context& ctx) {
  if (Size() == 0) return;

  std::vector<std::pair<NTermID, NodeID>> stack;
  stack.emplace_back(GetRule(NodeID(0), ctx).Nonterm(), NodeID(0));

  for (size_t i = 0; i < Size(); i++) {
    NodeID node_id(i);
    const NTermID& nonterm = GetRule(node_id, ctx).Nonterm();

    if (stack.size() == 0)
      throw exceptions::fuzzuf_runtime_error("Not a valid tree for unparsing!",
                                             __FILE__, __LINE__);

    auto [nterm_id, node] = stack.back();
    stack.pop_back();
    if (nterm_id != nonterm)
      throw exceptions::fuzzuf_runtime_error("Not a valid tree for unparsing!",
                                             __FILE__, __LINE__);

    _paren[i] = node;

    const Rule& rule = GetRule(node_id, ctx);
    std::vector<NTermID> nonterms = rule.Nonterms();
    for (auto it = nonterms.crbegin(); it != nonterms.crend(); ++it) {
      stack.emplace_back(*it, node_id);
    }
  }
}

/**
 * @fn
 * Calculate size information.
 * @brief Calculate sizes
 */
void Tree::CalcSizes() {
  for (size_t& size : _sizes) size = 1;

  for (size_t i = Size() - 1; i > 0; i--)
    _sizes.at(static_cast<size_t>(_paren.at(i))) += _sizes[i];
}

/**
 * @fn
 * @brief Get the slice of rules by node IDs.
 * @param (from) Start node ID of slice
 * @param (to) End node ID of slice
 * @return Vector of RuleIDOrCustom derived from slice
 */
std::vector<RuleIDOrCustom> Tree::Slice(const NodeID& from,
                                        const NodeID& to) const {
  // FIXME: Copy happens (although RuleIDOrCustom is small)
  //        We should return pair of iterators
  return std::vector<RuleIDOrCustom>(_rules.begin() + static_cast<size_t>(from),
                                     _rules.begin() + static_cast<size_t>(to));
}

/**
 * @fn
 * Get parent node ID by the child node ID.
 * @brief Get parent node ID of a node
 * @param (n) Node ID to get parent of
 * @return Parent node ID (std::nullopt if the node is root)
 */
std::optional<NodeID> Tree::GetParent(const NodeID& n) const {
  if (static_cast<size_t>(n) != 0) {
    return _paren.at(static_cast<size_t>(n));
  } else {
    /* Return none if root node */
    return std::nullopt;
  }
}

/**
 * @fn
 * Get the rule ID of a node.
 * @brief Get rule ID
 * @param (n) Node ID
 * @throw std::out_of_range Node ID is invalid
 * @return Rule ID
 */
const RuleID& Tree::GetRuleID(const NodeID& n) const {
  return _rules.at(static_cast<size_t>(n)).ID();
}

/**
 * @fn
 * Get the subtree size of a node.
 * @brief Get subtree size by node ID
 * @param (n) Node ID
 * @throw std::out_of_range Node ID is invalid
 * @return Subtree size
 */
size_t Tree::SubTreeSize(const NodeID& n) const {
  return _sizes.at(static_cast<size_t>(n));
}

/**
 * @fn
 * Construct TreeMutation by this tree and a new tree
 * @brief Create a TreeMutation instance
 * @param (n) Node ID to replace
 * @param (other) Tree to mutate
 * @param (other_node) Node ID to replace with
 * @return TreeMutation instance
 */
TreeMutation Tree::MutateReplaceFromTree(const NodeID& n, const Tree& other,
                                         const NodeID& other_node) const {
  size_t old_size = SubTreeSize(n);
  size_t new_size = other.SubTreeSize(other_node);
  return TreeMutation(
      std::move(Slice(NodeID(0), n)),                             // prefix
      std::move(other.Slice(other_node, other_node + new_size)),  // repl
      std::move(Slice(n + old_size, NodeID(_rules.size())))       // postfix
  );
}

/**
 * @fn
 * Get the number of rules that exists in the tree.
 * @brief Get the number of current rules
 * @return Number of rules
 */
size_t Tree::Size() const { return _rules.size(); }

/**
 * @fn
 * Create a deep copy of the tree.
 * @brief Copy this tree
 * @return New tree copied from current tree
 */
Tree Tree::ToTree(Context&) const {  // Context is unused in Tree impl
  return Tree(_rules, _sizes, _paren);
}

/**
 * @fn
 * Get the rule of a node.
 * @brief Get rule by node ID
 * @param (n) Node ID
 * @param (ctx) Context
 * @throw std::out_of_range Node ID is invalid
 * @return Rule corresponding to node ID
 */
const Rule& Tree::GetRule(const NodeID& n, Context& ctx) const {
  return ctx.GetRule(GetRuleID(n));
}

/**
 * @fn
 * Get the custom rule data of a node.
 * @brief Get custom rule data by node ID
 * @param (n) Node ID
 * @throw std::out_of_range Node ID is invalid
 * @return Data of rule (throws exception if rule is not Custom)
 */
const std::string& Tree::GetCustomRuleData(const NodeID& n) const {
  return _rules.at(static_cast<size_t>(n)).Data();
}

/**
 * @fn
 * Get the RuleIROrCustom instance of a node.
 * @brief Get rule ID or custom by node ID
 * @param (n) Node ID
 * @throw std::out_of_range Node ID is invalid
 * @return RuleIDOrCustom corresponding to node ID
 */
const RuleIDOrCustom& Tree::GetRuleOrCustom(const NodeID& n) const {
  return _rules.at(static_cast<size_t>(n));
}

/**
 * @fn
 * Clear every rule, size, and parent information.
 * @brief Remove every rule
 */
void Tree::Truncate() {
  _rules.clear();
  _sizes.clear();
  _paren.clear();
}

/**
 * @fn
 * Generate a random tree from a nonterminal symbol.
 * @brief Generate tree from nonterminal
 * @param (start) Nonterminal symbol ID
 * @param (len) Maximum length for getting random rule for `start`
 * @param (ctx) Context
 */
void Tree::GenerateFromNT(const NTermID& start, size_t len, Context& ctx) {
  const RuleID& rid = ctx.GetRandomRuleForNT(start, len);
  GenerateFromRule(rid, len - 1, ctx);
}

/**
 * @fn
 * Generate a random tree from a specific rule of a nonterminal.
 * @brief Generate tree from rule
 * @param (ruleid) Rule ID
 * @param (max_len) Maximum length
 * @param (ctx) Context
 */
void Tree::GenerateFromRule(const RuleID& ruleid, size_t max_len,
                            Context& ctx) {
  if (std::holds_alternative<PlainRule>(ctx.GetRule(ruleid).value())) {
    /* PlainRule or ScriptRule */
    Truncate();
    _rules.emplace_back(ruleid);
    _sizes.emplace_back(0);
    _paren.emplace_back(0);
    ctx.GetRule(ruleid).Generate(*this, ctx, max_len);

    _sizes[0] = _rules.size();

  } else {
    // NOTE: RegExpRule should work differently here
    throw exceptions::not_implemented("Only PlainRule is supported", __FILE__,
                                      __LINE__);
  }
}

/**
 * @fn
 * Calculate the recursions of this tree.
 * @brief Calculate recursions
 * @param (ctx) Context
 * @return Vector of recursion info if successful (std::optional)
 */
std::optional<std::vector<RecursionInfo>> Tree::CalcRecursions(Context& ctx) {
  std::vector<RecursionInfo> ret;
  std::unordered_set<NTermID> done_nterms;

  for (const RuleIDOrCustom& rule : _rules) {
    const NTermID& nterm = ctx.GetNT(rule);
    if (done_nterms.find(nterm) == done_nterms.end()) {
      std::optional<RecursionInfo> ri = RecursionInfo::New(*this, nterm, ctx);
      if (ri) {
        ret.emplace_back(ri.value());
      }

      done_nterms.insert(nterm);
    }
  }

  if (ret.empty()) return std::nullopt;

  return ret;
}

/**
 * @fn
 * Get the rule at a specific node.
 * @brief Get rule at specific node ID
 * @param (n) Node ID
 * @throw exceptions::fuzzuf_runtime_error Node ID is invalid
 * @return RuleIDOrCustom
 */
const RuleIDOrCustom& TreeMutation::GetAt(const NodeID& n) const {
  size_t i = static_cast<size_t>(n);
  size_t end0 = _prefix.size();
  size_t end1 = end0 + _repl.size();
  size_t end2 = end1 + _postfix.size();

  if (i < end0) {
    return _prefix[i];

  } else if (i < end1) {
    return _repl[i - end0];

  } else if (i < end2) {
    return _postfix[i - end1];
  }

  throw exceptions::fuzzuf_runtime_error("Index out of bound for rule access",
                                         __FILE__, __LINE__);
}

/**
 * @fn
 * Get the rule ID of a node.
 * @brief Get rule ID by node ID
 * @param (n) Node ID
 * @throw exceptions::fuzzuf_runtime_error Node ID is invalid
 * @return Rule ID
 */
const RuleID& TreeMutation::GetRuleID(const NodeID& n) const {
  return GetAt(n).ID();
}

/**
 * @fn
 * Calculate size of this TreeMutation instance.
 * @brief Get the size of this tree
 * @return Number of rules
 */
size_t TreeMutation::Size() const {
  return _prefix.size() + _repl.size() + _postfix.size();
}

/**
 * @fn
 * Create a deep copy of this TreeMutation instance.
 * @brief Create a new tree from TreeMutation
 * @return New tree copied from current tree
 */
Tree TreeMutation::ToTree(Context& ctx) const {
  std::vector<RuleIDOrCustom> vec;
  vec.insert(vec.end(), _prefix.begin(), _prefix.end());
  vec.insert(vec.end(), _repl.begin(), _repl.end());
  vec.insert(vec.end(), _postfix.begin(), _postfix.end());
  return Tree(std::move(vec), ctx);
}

/**
 * @fn
 * Get the rule of a node.
 * @brief Get rule by node ID
 * @param (n) Node ID
 * @param (ctx) Context
 * @throw std::out_of_range Node ID is invalid
 * @return Rule corresponding to node ID
 */
const Rule& TreeMutation::GetRule(const NodeID& n, Context& ctx) const {
  return ctx.GetRule(GetRuleID(n));
}

/**
 * @fn
 * Get the RuleIDOrCustom of a node.
 * @brief Get rule ID or custom by node ID
 * @param (n) Node ID
 * @throw std::out_of_range Node ID is invalid
 * @return RuleIDOrCustom corresponding to node ID
 */
const RuleIDOrCustom& TreeMutation::GetRuleOrCustom(const NodeID& n) const {
  return GetAt(n);
}

/**
 * @fn
 * Get the custom rule data of a node.
 * @brief Get custom rule data by node ID
 * @param (n) Node ID
 * @throw std::out_of_range Node ID is invalid
 * @return Data of rule (throws exception if rule is not Custom)
 */
const std::string& TreeMutation::GetCustomRuleData(const NodeID& n) const {
  return GetAt(n).Data();
}

/**
 * @fn
 * Get the nonterminal ID of a node.
 * @brief Get nonterminal ID by NodeID
 * @param (n) NodeID
 * @param (ctx) Context
 * @throw std::out_of_range Node ID is invalid
 * @return Nonterminal symbol ID
 */
const NTermID& TreeLike::GetNontermID(const NodeID& n, Context& ctx) const {
  return GetRule(n, ctx).Nonterm();
}

/**
 * @fn
 * Unparse (sub)tree derived from a node into a testcase.
 * @brief Unparse a subtree into string
 * @param (id) Node ID
 * @param (ctx) Context
 * @param (data) Reference to string to store the result
 */
void TreeLike::Unparse(const NodeID& id, Context& ctx,
                       std::string& data) const {
  Unparser(id, data, *this, ctx).Unparse();
}

/**
 * @fn
 * Unparse the whole tree into a testcase.
 * @brief Unparse this tree into string
 * @param (ctx) Context
 * @param (data) Reference to string to store result
 */
void TreeLike::UnparseTo(Context& ctx, std::string& data) const {
  Unparse(NodeID(0), ctx, data);
}

std::string TreeLike::UnparseNodeToVec(const NodeID& n, Context& ctx) const {
  std::string data;
  Unparse(n, ctx, data);
  return data;
}

std::string TreeLike::UnparseToVec(Context& ctx) const {
  return UnparseNodeToVec(NodeID(0), ctx);
}

/**
 * @fn
 * Construct an Unparser instance.
 * @brief Construct Unparser
 * @param (nid) Node ID
 * @param (w) Data
 * @param (tree) Tree
 * @param (ctx) Context
 */
Unparser::Unparser(const NodeID& nid, std::string& w, const TreeLike& tree,
                   Context& ctx)
    : _tree(tree), _w(w), _ctx(ctx) {
  _i = static_cast<size_t>(nid);
  _stack.emplace_back(tree.GetRule(NodeID(_i), ctx).Nonterm());
}

/**
 * @fn
 * @brief Forward one step for unparse
 * @return True if successful
 */
bool Unparser::UnparseOneStep() {
  if (_stack.size() == 0) return false;

  auto& data = _stack.back().value();
  _stack.pop_back();

  if (std::holds_alternative<Term>(data)) {
    // Terminal symbol
    Write(std::get<Term>(data));

  } else if (std::holds_alternative<NTerm>(data)) {
    // Nonterminal symbol
    Nonterm(std::get<NTerm>(data));

  } else {
    throw exceptions::unreachable("Unexpected stack top", __FILE__, __LINE__);
  }

  return true;
}

/**
 * @fn
 * @brief Operation for terminal symbols
 * @param (data) Term
 */
void Unparser::Write(const std::string& data) {
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
void Unparser::Nonterm(const NTermID& nt) { NextRule(nt); }

/**
 * @fn
 * @brief Operation for nonterminal symbols
 * @param (nt) Nonterminal
 */
void Unparser::NextRule(const NTermID& nt) {
  NodeID nid(_i);
  const Rule& rule = _tree.GetRule(nid, _ctx);
  DEBUG_ASSERT(nt == rule.Nonterm());
  UNUSED(nt);

  _i++;

  if (std::holds_alternative<PlainRule>(rule.value())) {
    // Operation for plain rules
    NextPlain(std::get<PlainRule>(rule.value()));

  } else {
    throw exceptions::not_implemented("Only PlainRule is supported", __FILE__,
                                      __LINE__);
  }
}

/**
 * @fn
 * @brief Operation for plain rules
 * @param (r) Plain rule
 */
void Unparser::NextPlain(const PlainRule& r) {
  for (auto it = r.children.crbegin(); it != r.children.crend(); it++) {
    const RuleChild& rule_child = *it;

    if (std::holds_alternative<Term>(rule_child.value())) {
      // Push as terminal
      _stack.emplace_back(std::get<Term>(rule_child.value()));

    } else if (std::holds_alternative<NTerm>(rule_child.value())) {
      // Push as tonterminal
      _stack.emplace_back(std::get<NTerm>(rule_child.value()));

    } else {
      throw exceptions::unreachable("Unexpected RuleChild type", __FILE__,
                                    __LINE__);
    }
  }
}

/**
 * @fn
 * @brief Unparse all rules
 * @return Node ID (step count)
 */
NodeID Unparser::Unparse() {
  // Unparse while stack is not empty
  while (UnparseOneStep())
    ;

  return NodeID(_i);
}

}  // namespace fuzzuf::algorithm::nautilus::grammartec
