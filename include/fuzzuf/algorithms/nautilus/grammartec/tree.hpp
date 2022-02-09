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

#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

class RecursionInfo;
class Tree;
class TreeLike;
class TreeMutation;
class Unparser;
class UnparserStep;


class TreeLike {
public:
  virtual const RuleID& GetRuleID(const NodeID& n) const = 0;
  virtual size_t Size() const = 0;
  virtual Tree ToTree(Context& ctx) const = 0;
  virtual const Rule& GetRule(const NodeID& n, Context& ctx) const = 0;
  virtual const RuleIDOrCustom& GetRuleOrCustom(const NodeID& n) const = 0;
  virtual const std::string& GetCustomRuleData(const NodeID& n) const = 0;
  const NTermID& GetNontermID(const NodeID& n, Context& ctx) const;

  void Unparse(const NodeID& id, Context& ctx, std::string& data) const;
  void UnparseTo(Context& ctx, std::string& data) const;
  std::string UnparseNodeToVec(const NodeID& n, Context& ctx) const;
  std::string UnparseToVec(Context& ctx) const;
};


class Tree: public TreeLike {
public:
  Tree(std::vector<RuleIDOrCustom> rules, Context &ctx);
  Tree(std::vector<RuleIDOrCustom> rules,
       std::vector<size_t> sizes,
       std::vector<NodeID> paren)
    : _rules(rules), _sizes(sizes), _paren(paren) {};
  std::vector<RuleIDOrCustom>& rules() { return _rules; }
  std::vector<size_t>& sizes() { return _sizes; }
  std::vector<NodeID>& paren() { return _paren; }

  virtual const RuleID& GetRuleID(const NodeID& n) const;
  virtual size_t Size() const;
  virtual Tree ToTree(Context& ctx) const;
  virtual const Rule& GetRule(const NodeID& n, Context& ctx) const;
  virtual const RuleIDOrCustom& GetRuleOrCustom(const NodeID& n) const;
  virtual const std::string& GetCustomRuleData(const NodeID& n) const;
  size_t SubTreeSize(const NodeID& n) const;
  TreeMutation MutateReplaceFromTree(NodeID n, Tree other, NodeID other_node);

  void CalcSubTreeSizesAndParents(Context &ctx);
  void CalcParents(Context &ctx);
  void CalcSizes();
  std::vector<RuleIDOrCustom> Slice(const NodeID& from, const NodeID& to) const;
  std::optional<NodeID> GetParent(const NodeID& n) const;

  void Truncate();
  void GenerateFromNT(const NTermID& start, size_t len, Context& ctx);
  void GenerateFromRule(const RuleID& ruleid, size_t max_len, Context& ctx);

  std::optional<std::vector<RecursionInfo>> CalcRecursions(Context& ctx);

private:
  std::vector<RuleIDOrCustom> _rules;
  std::vector<size_t> _sizes;
  std::vector<NodeID> _paren;
};

class TreeMutation: public TreeLike {
public:
  TreeMutation(std::vector<RuleIDOrCustom> prefix,
               std::vector<RuleIDOrCustom> repl,
               std::vector<RuleIDOrCustom> postfix)
    : _prefix(prefix), _repl(repl), _postfix(postfix) {}
  const std::vector<RuleIDOrCustom>& prefix() const { return _prefix; }
  const std::vector<RuleIDOrCustom>& repl() const { return _repl; }
  const std::vector<RuleIDOrCustom>& postfix() const { return _postfix; }
  const RuleIDOrCustom& GetAt(const NodeID& n) const;

  virtual const RuleID& GetRuleID(const NodeID& n) const;
  virtual size_t Size() const;
  virtual Tree ToTree(Context& ctx) const;
  virtual const Rule& GetRule(const NodeID& n, Context& ctx) const;
  virtual const RuleIDOrCustom& GetRuleOrCustom(const NodeID& n) const;
  virtual const std::string& GetCustomRuleData(const NodeID& n) const;

private:
  std::vector<RuleIDOrCustom> _prefix;
  std::vector<RuleIDOrCustom> _repl;
  std::vector<RuleIDOrCustom> _postfix;
};


// NOTE: TScript (as well as PushBuffer) not implemented
struct UnparseStep {
public:
  UnparseStep() : _step(0) {}
  UnparseStep(Term t) : _step(t) {}
  UnparseStep(NTermID nt) : _step(nt) {}
  const std::variant<Term, NTerm> value() const { return _step; }

private:
  std::variant<Term, NTerm> _step;
};


struct Unparser {
public:
  Unparser(const NodeID& nid,
           std::string& w,
           const TreeLike& tree,
           Context& ctx);
  bool UnparseOneStep();
  void Write(const std::string& data);
  void Nonterm(const NTermID& nt);
  void NextRule(const NTermID& nt);
  void NextPlain(const PlainRule& r);
  NodeID Unparse();

private:
  const TreeLike& _tree;
  std::vector<UnparseStep> _stack;
  std::vector<std::stringstream> _buffers;
  std::string& _w;
  size_t _i;
  Context& _ctx;
};

} // namespace fuzzuf::algorithms::nautilus::grammartec
