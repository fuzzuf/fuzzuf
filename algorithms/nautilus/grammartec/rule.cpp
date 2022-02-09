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
#include <iomanip>
#include <iterator>
#include <regex>
#include <sstream>
#include <string>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
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
Rule::Rule(Context& ctx, const std::string& nonterm, const std::string& format) {
  std::vector<RuleChild> children = Rule::Tokenize(format, ctx);
  std::vector<NTermID> nonterms;

  // Filter only NTerm items from children
  for (RuleChild child: children) {
    if (std::holds_alternative<NTerm>(child.value())) {
      nonterms.emplace_back(std::get<NTerm>(child.value()));
    }
  }

  _rule = PlainRule{ctx.AquireNTID(nonterm), children, nonterms};
}

/**
 * @fn
 * @brief Describe this rule
 * @param (ctx) Context
 * @return Human-readable string of this rule
 */
std::string Rule::DebugShow(Context& ctx) {
  return std::visit([&ctx](auto r) { return r.DebugShow(ctx); }, _rule);
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
std::vector<RuleChild> Rule::Tokenize(const std::string& format, Context& ctx) {
  static std::regex TOKENIZER(R"((\{[^}\\]+\})|((?:[^{\\]|\\\{|\\\}|\\)+))");

  std::vector<RuleChild> r;
  for (std::sregex_iterator it(format.begin(), format.end(), TOKENIZER), end;
       it != end;
       ++it) {
    std::smatch m = *it;

    if (m[1].matched) {
      // NT: "{A:a}"
      r.emplace_back(m.str(), ctx);
    } else if (m[2].matched) {
      // "abc\{def\}ghi" --> "abc{def}ghi"
      r.emplace_back(Rule::Unescape(m.str()));
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
 * @return Vector of NTermID of this rule
 */
std::vector<NTermID> Rule::Nonterms() {
  // TODO: reference it
  if (std::holds_alternative<PlainRule>(_rule)) {
    return std::get<PlainRule>(_rule).nonterms;
  } else {
    throw exceptions::not_implemented(
      "Only PlainRule is supported", __FILE__, __LINE__
    );
  }
}

/**
 * @fn
 * @brief Get number of nonterms
 * @return Number of nonterms
 */
size_t Rule::NumberOfNonterms() {
  return Nonterms().size();
}

/**
 * @fn
 * @brief Get matching nonterm
 * @return NTermID of this rule
 */
NTermID Rule::Nonterm() {
  return std::visit([](auto r) { return r.nonterm; }, _rule);
}

size_t Rule::Generate(Tree& tree, Context& ctx, size_t len) {
  size_t minimal_needed_len = 0;
  for (NTermID nt: Nonterms())
    minimal_needed_len += ctx.GetMinLenForNT(nt);
  assert (minimal_needed_len <= len);

  size_t remaining_len = len - minimal_needed_len;

  size_t total_size = 1;
  NodeID paren(tree.Size() - 1);

  std::vector<NTermID> nonterms = Nonterms();
  for (size_t i = 0; i < nonterms.size(); i++) {
    size_t cur_child_max_len;
    std::vector<NTermID> new_nterms(nonterms.begin() + i, nonterms.end());

    if (new_nterms.size() != 0) {
      cur_child_max_len = ctx.GetRandomLen(new_nterms.size(), remaining_len);
    } else {
      cur_child_max_len = remaining_len;
    }
    cur_child_max_len += ctx.GetMinLenForNT(nonterms[i]);

    RuleID rid = ctx.GetRandomRuleForNT(nonterms[i], cur_child_max_len);
    // NOTE: RegExpRule should work differently here
    RuleIDOrCustom rule_or_custom = RuleIDOrCustom(rid);

    assert (tree.rules().size() == tree.sizes().size());
    assert (tree.paren().size() == tree.sizes().size());

    size_t offset = tree.Size();
    tree.rules().emplace_back(rule_or_custom);
    tree.sizes().emplace_back(0);
    tree.paren().emplace_back(0);

    size_t consumed_len = ctx.GetRule(rid).Generate(
      tree, ctx, cur_child_max_len - 1
    );
    tree.sizes()[offset] = consumed_len;
    tree.paren()[offset] = paren;

    assert (consumed_len <= cur_child_max_len);
    assert (consumed_len >= ctx.GetMinLenForNT(nonterms[i]));

    remaining_len += ctx.GetMinLenForNT(nonterms[i]);
    remaining_len -= consumed_len;
    total_size += consumed_len;
  }

  return total_size;
}

/**
 * @fn
 * @brief Construct RuleChild from literal
 * @param (lit) Literal string
 */
RuleChild::RuleChild(const std::string& lit) {
  _rule_child = lit;
}

/**
 * @fn
 * @brief Construct RuleChild from nonterminal
 * @param (nt) Nonterminal symbol
 * @param (ctx) Context
 */
RuleChild::RuleChild(const std::string& nt, Context& ctx) {
  std::string nonterm = SplitNTDescription(nt);
  _rule_child = NTerm(ctx.AquireNTID(nonterm));
}

/**
 * @fn
 * @brief Describe RuleChild as string
 * @param (ctx) Context
 * @return Human-readable string
 */
std::string RuleChild::DebugShow(Context& ctx) {
  if (std::holds_alternative<NTerm>(_rule_child)) {
    return ctx.NTIDToString(std::get<NTerm>(_rule_child));
  } else {
    return ShowBytes(std::get<Term>(_rule_child));
  }
}

/**
 * @fn
 * @brief Split nonterminal description
 * @param (nonterm) Nonterminal symbol
 * @return Extracted symbol
 */
std::string RuleChild::SplitNTDescription(const std::string& nonterm) {
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

/**
 * @fn
 * @brief Get RuleID of RuleIDOrCustom
 * @return RuleID
 */
const RuleID& RuleIDOrCustom::ID() const {
  if (std::holds_alternative<RuleID>(_rule_id_or_custom)) {
    return std::get<RuleID>(_rule_id_or_custom);
  } else {
    return std::get<Custom>(_rule_id_or_custom).first;
  }
}

/**
 * @fn
 * @brief Get data of RuleIDOrCustom
 * @return Data (exception thrown if rule is not Custom)
 */
const std::string& RuleIDOrCustom::Data() const {
  if (std::holds_alternative<RuleID>(_rule_id_or_custom)) {
    throw exceptions::fuzzuf_runtime_error(
      "Cannot get data on a normal rule", __FILE__, __LINE__
    );
  } else {
    return std::get<Custom>(_rule_id_or_custom).second;
  }
}

std::string PlainRule::DebugShow(Context& ctx) {
  std::string res = "";
  for (size_t i = 0; i < children.size(); i++) {
    res += children[i].DebugShow(ctx);
    if (i != children.size() - 1) res += ", ";
  }
  return ctx.NTIDToString(nonterm) + " => " + res;
}

std::string ShowBytes(const std::string& bs) {
  std::stringstream ss;
  for (size_t i = 0; i < bs.size(); i++) {
    char c = bs[i];
    if (0x20 <= c && c <= 0x7e) {
      ss << c;
    } else {
      switch (c) {
        case '\t': ss << "\\t"; break;
        case '\r': ss << "\\r"; break;
        case '\n': ss << "\\n"; break;
        case '\'': ss << "\\'"; break;
        case '"': ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        default:
          ss << "\\x"
             << std::setfill('0') << std::setw(2)
             << std::hex << (uint8_t)c;
          break;
      }
    }
  }

  return ss.str();
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
