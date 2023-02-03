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
 * @file rule.hpp
 * @brief Grammar rules and parser/unparser
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_RULE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_RULE_HPP

#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

class Tree;
class Context;

using Term = std::string;
using NTerm = NTermID;

/* RuleChild: A terminal or nonterminal symbol */
class RuleChild {
 public:
  RuleChild(const std::string& lit);
  RuleChild(const std::string& nt, Context& ctx);
  const std::variant<Term, NTerm> value() const { return _rule_child; }
  inline bool operator==(const RuleChild& others) const {
    return _rule_child == others.value();
  }

  std::string DebugShow(Context& ctx) const;
  std::string SplitNTDescription(const std::string& nonterm) const;

 private:
  std::variant<Term, NTerm> _rule_child;
};

/* RuleIDOrCustom: Store a general or custom rule */
using Custom = std::pair<RuleID, std::string>;

class RuleIDOrCustom {
 public:
  RuleIDOrCustom() = delete;
  RuleIDOrCustom(const RuleID& rid) : _rule_id_or_custom(rid) {}
  RuleIDOrCustom(const RuleID& rid, const std::string& s)
      : _rule_id_or_custom(Custom(rid, s)) {}
  const std::variant<RuleID, Custom> value() const {
    return _rule_id_or_custom;
  }
  inline bool operator==(const RuleIDOrCustom& others) const {
    return _rule_id_or_custom == others.value();
  }

  const RuleID& ID() const;
  const std::string& Data() const;

 private:
  std::variant<RuleID, Custom> _rule_id_or_custom;
};

struct PlainRule {
  PlainRule(){};  // for variant
  PlainRule(const NTermID& nonterm, std::vector<RuleChild>&& children,
            std::vector<NTermID>&& nonterms)
      : nonterm(nonterm),
        children(std::move(children)),
        nonterms(std::move(nonterms)) {}
  std::string DebugShow(Context& ctx) const;

  NTermID nonterm;
  std::vector<RuleChild> children;
  std::vector<NTermID> nonterms;
};

/* Rule: A rule and its parser */
class Rule {
 public:
  Rule(Context& ctx, const std::string& nonterm, const std::string& format);
  const std::variant<PlainRule>& value() const { return _rule; }

  std::string DebugShow(Context& ctx) const;
  const std::vector<NTermID>& Nonterms() const;
  size_t NumberOfNonterms() const;
  const NTermID& Nonterm() const;
  size_t Generate(Tree& tree, Context& ctx, size_t len) const;

  static std::string Unescape(const std::string& bytes);
  static std::vector<RuleChild> Tokenize(const std::string& format,
                                         Context& ctx);

 private:
  // TODO: Implement ScriptRule and RegExpRule
  std::variant<PlainRule> _rule;
};

std::string ShowBytes(const std::string& bs);

}  // namespace fuzzuf::algorithm::nautilus::grammartec

#endif
