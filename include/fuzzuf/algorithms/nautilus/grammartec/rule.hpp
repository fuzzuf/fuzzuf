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
 * @file rule.hpp
 * @brief Rule for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <variant>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

class Context;

using Term = std::string;
using NTerm = NTermID;

struct RuleChild {
public:
  RuleChild(const std::string& lit);
  RuleChild(const std::string& nt, Context& ctx);
  const std::variant<Term, NTerm> value() const { return _rule_child; }
  inline bool operator==(const RuleChild& others) const {
    return _rule_child == others.value();
  }

  std::string DebugShow(Context& ctx);
  std::string SplitNTDescription(const std::string& nonterm);

private:
  std::variant<Term, NTerm> _rule_child;
};


struct PlainRule {
  PlainRule() {} // default constructor for variant
  PlainRule(NTermID nonterm,
            std::vector<RuleChild> children,
            std::vector<NTermID> nonterms)
    : nonterm(nonterm),
      children(children),
      nonterms(nonterms) {}
  std::string DebugShow(Context& ctx);

  NTermID nonterm;
  std::vector<RuleChild> children;
  std::vector<NTermID> nonterms;
};

struct ScriptRule {
  ScriptRule(NTermID nonterm,
             std::vector<NTermID> nonterms)
    : nonterm(nonterm),
      nonterms(nonterms) {}
  std::string DebugShow(Context& ctx);

  NTermID nonterm;
  std::vector<NTermID> nonterms;
  //PyObject script;
};

struct RegExpRule {
  RegExpRule(NTermID nonterm)
    : nonterm(nonterm) {}
  std::string DebugShow(Context& ctx);

  NTermID nonterm;
  // Hir hir;
};


struct Rule {
public:
  Rule(Context& ctx, const std::string& nonterm, const std::string& format);
  std::variant<PlainRule, ScriptRule, RegExpRule> value() { return _rule; }

  std::string DebugShow(Context& ctx);
  std::string Unescape(const std::string& bytes);
  std::vector<RuleChild> Tokenize(const std::string& format, Context& ctx);
  std::vector<NTermID> Nonterms();
  NTermID Nonterm();

private:
  std::variant<PlainRule, ScriptRule, RegExpRule> _rule;
};

std::string ShowBytes(std::string bs);

} // namespace fuzzuf::algorithms::nautilus::grammartec
