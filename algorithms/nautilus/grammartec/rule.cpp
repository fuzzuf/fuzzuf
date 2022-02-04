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
#include <iterator>
#include <regex>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

/**
 * @fn
 * @brief Construct Rule from format
 * @param (ctx) Context
 * @param (nonterm) Nonterminal symbol
 * @param (format) Format string
 */
Rule::Rule(Context& ctx, std::string nonterm, std::string format) {
  std::vector<RuleChild> children = Rule::Tokenize(format, ctx);
  std::vector<NTermID> nonterms;

  // Filter only NTerm items from children
  for (RuleChild child: children) {
    if (std::holds_alternative<NTerm>(child.value())) {
      nonterms.push_back(std::get<NTerm>(child.value()));
    }
  }

  _rule = PlainRule{ctx.AquireNTID(nonterm), children, nonterms};
}

/**
 * @fn
 * @brief Unescape "\{" and "\}" in a string
 * @param (bytes) String to unescape
 * @return Unescaped string
 */
std::string Rule::Unescape(const std::string& bytes) {
  if (bytes.size() < 2) {
    // Nothing to escape
    return bytes;
  }

  /* Convert "\{" into "{" and "\}" into "}" */
  std::string res = "";
  size_t i;
  for (i = 0; i < bytes.size(); i++) {
    if (bytes[i] == '\\' && bytes[i+1] == '{') {
      res += "{";
      i++;
    } else if (bytes[i] == '\\' && bytes[i+1] == '}') {
      res += "}";
      i++;
    } else {
      res += bytes[i];
    }
  }

  if (i < bytes.size()) {
    res += bytes[bytes.size() - 1];
  }

  return res;
}

/**
 * @fn
 * @brief Tokenize from format string
 * @param (format) String to tokenize
 * @param (ctx) Context
 * @return Children rules
 */
std::vector<RuleChild> Rule::Tokenize(std::string& format, Context& ctx) {
  static std::regex TOKENIZER(R"((\{[^}\\]+\})|((?:[^{\\]|\\\{|\\\}|\\)+))");

  std::vector<RuleChild> r;
  for (std::sregex_iterator it(format.begin(), format.end(), TOKENIZER), end;
       it != end;
       ++it) {
    std::smatch m = *it;

    if (m[1].matched) {
      // NT: "{A:a}"
      r.push_back(RuleChild(m.str(), ctx));
    } else if (m[2].matched) {
      // "abc\{def\}ghi" --> "abc{def}ghi"
      r.push_back(RuleChild(Rule::Unescape(m.str())));
    } else {
      throw exceptions::unreachable(
        "Unexpected capturing group", __FILE__, __LINE__
      );
    }
  }

  ctx = ctx;
  return r;
}

/**
 * @fn
 * @brief Get matching nonterms
 * @return NTermID of this rule
 */
std::vector<NTermID> Rule::Nonterms() {
  if (std::holds_alternative<PlainRule>(_rule)) {
    return std::get<PlainRule>(_rule).nonterms;
  } else if (std::holds_alternative<ScriptRule>(_rule)) {
    return std::get<ScriptRule>(_rule).nonterms;
  } else {
    return {};
  }
}

/**
 * @fn
 * @brief Construct RuleChild from literal
 * @param (lit) Literal string
 */
RuleChild::RuleChild(std::string lit) {
  _rule_child = lit;
}

/**
 * @fn
 * @brief Construct RuleChild from nonterminal
 * @param (nt) Nonterminal symbol
 * @param (ctx) Context
 */
RuleChild::RuleChild(std::string nt, Context& ctx) {
  std::string nonterm = SplitNTDescription(nt);
  _rule_child = NTerm(ctx.AquireNTID(nonterm));
}

/**
 * @fn
 * @brief Split nonterminal description
 * @param (nonterm) Nonterminal symbol
 * @return Extracted symbol
 */
std::string RuleChild::SplitNTDescription(std::string& nonterm) {
  std::smatch m;
  static std::regex SPLITTER(R"(^\{([A-Z][a-zA-Z_\-0-9]*)(?::([a-zA-Z_\-0-9]*))?\}$)");

  // Splits {A:a} or {A} into A and maybe a
  if (!std::regex_match(nonterm, m, SPLITTER)) {
    throw exceptions::execution_failure(
      Util::StrPrintf("Could not interpret Nonterminal %s. "
                      "Nonterminal Descriptions need to match "
                      "start with a capital letter and con only "
                      "contain [a-zA-Z_-0-9]", nonterm),
      __FILE__, __LINE__
    );
  }

  return m[1].str();
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
