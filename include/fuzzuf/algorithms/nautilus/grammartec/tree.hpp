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

#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

class TreeLike {
public:
  virtual RuleID GetRuleID(NodeID n) = 0;
  virtual size_t Size() = 0;
  virtual Tree ToTree(Context& ctx) = 0;
  virtual Rule& GetRule(NodeID n, Context& ctx) = 0;
  virtual RuleIDOrCustom& GetRuleOrCustom(NodeID n) = 0;
  virtual std::string GetCustomRuleData(NodeID n) = 0;
  NTermID GetNontermID(NodeID n, Context& ctx);

  void Unparse(NodeID id, Context& ctx, std::string& data);
  void UnparseTo(Context& ctx, std::string& data);
  std::string UnparseNodeToVec(NodeID n, Context& ctx);
  std::string UnparseToVec(Context& ctx);
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

  virtual RuleID GetRuleID(NodeID n);
  virtual size_t Size();
  virtual Tree ToTree(Context& ctx);
  virtual Rule& GetRule(NodeID n, Context& ctx);
  virtual RuleIDOrCustom& GetRuleOrCustom(NodeID n);
  virtual std::string GetCustomRuleData(NodeID n);

  void CalcSubTreeSizesAndParents(Context &ctx);
  void CalcParents(Context &ctx);
  void CalcSizes();

  void Truncate();
  void GenerateFromNT(NTermID start, size_t len, Context& ctx);
  void GenerateFromRule(RuleID ruleid, size_t max_len, Context& ctx);

private:
  std::vector<RuleIDOrCustom> _rules;
  std::vector<size_t> _sizes;
  std::vector<NodeID> _paren;
};


// NOTE: TScript not implemented
using TPushBuffer = int;

struct UnparseStep {
public:
  UnparseStep() : _step(0) {}
  UnparseStep(Term t) : _step(t) {}
  UnparseStep(NTermID nt) : _step(nt) {}
  std::variant<TPushBuffer, Term, NTerm> value() { return _step; }

private:
  std::variant<TPushBuffer, Term, NTerm> _step;
};


struct Unparser {
public:
  Unparser(NodeID nid, std::string& w, TreeLike& tree, Context& ctx);
  bool UnparseOneStep();
  void Write(std::string& data);
  void Nonterm(NTermID nt);
  void PushBuffer();
  void NextRule(NTermID nt);
  void NextPlain(PlainRule r);
  NodeID Unparse();

private:
  TreeLike& _tree;
  std::vector<UnparseStep> _stack;
  std::vector<std::stringstream> _buffers;
  std::string& _w;
  size_t _i;
  Context& _ctx;
};

} // namespace fuzzuf::algorithms::nautilus::grammartec
