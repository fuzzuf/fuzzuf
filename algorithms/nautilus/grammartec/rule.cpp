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
 *
 * @details This file defines Rule class.
 *          Rule parses terminal and nonterminal symbols written in text.
 *          It can also unparse a rule into text.
 */
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"

#include <iomanip>
#include <iterator>
#include <regex>
#include <sstream>
#include <string>

#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

/**
 * @fn
 * Constructor of Rule class.
 * This constructor takes a plain-text rule.
 * @brief Construct Rule from format
 * @param (ctx) Context
 * @param (nonterm) String representation of nonterminal symbol
 * @param (format) Format string (expression) of the rule for @p nonterm
 *
 * @details Nonterminal symbol must follow `{ABC:xyz}` format
 *          where `ABC` indicates the nonterminal and `:xyz` is
 *          an optional comment.
 *          The format string is what the nonterminal should be
 *          replaced with.
 *          You can use any nonterminal symbols in this format.
 */
Rule::Rule(Context& ctx, const std::string& nonterm,
           const std::string& format) {
  std::vector<RuleChild> children = Rule::Tokenize(format, ctx);
  std::vector<NTermID> nonterms;

  // Filter only NTerm items from children
  for (RuleChild child : children) {
    if (std::holds_alternative<NTerm>(child.value())) {
      nonterms.emplace_back(std::get<NTerm>(child.value()));
    }
  }

  _rule = PlainRule{ctx.AquireNTID(nonterm), std::move(children),
                    std::move(nonterms)};
}

/**
 * @fn
 * Describe this rule into a human-readable string.
 * @brief Describe this rule
 * @param (ctx) Context
 * @return Human-readable string of this rule
 */
std::string Rule::DebugShow(Context& ctx) const {
  return std::visit([&ctx](auto r) { return r.DebugShow(ctx); }, _rule);
}

/**
 * @fn
 * Remove every backslash before `{` and `}`
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
  std::string res;
  size_t i;
  for (i = 0; i < bytes.size() - 1; i++) {
    if (bytes[i] == '\\' && bytes[i + 1] == '{') {
      res += "{";
      i++;
    } else if (bytes[i] == '\\' && bytes[i + 1] == '}') {
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
 * Parse an expression of a rule and return a list of RuleChild.
 * @brief Tokenize format string
 * @param (format) String to tokenize
 * @param (ctx) Context
 * @throw exceptions::unreachable @p format is an invalid expression
 * @return Children rules
 */
std::vector<RuleChild> Rule::Tokenize(const std::string& format, Context& ctx) {
  static std::regex TOKENIZER(R"((\{[^}\\]+\})|((?:[^{\\]|\\\{|\\\}|\\)+))");

  std::vector<RuleChild> r;
  for (std::sregex_iterator it(format.begin(), format.end(), TOKENIZER), end;
       it != end; ++it) {
    std::smatch m = *it;

    if (m[1].matched) {
      // NT: "{A:a}"
      r.emplace_back(m.str(), ctx);
    } else if (m[2].matched) {
      // "abc\{def\}ghi" --> "abc{def}ghi"
      r.emplace_back(Rule::Unescape(m.str()));
    } else {
      throw exceptions::unreachable("Unexpected capturing group", __FILE__,
                                    __LINE__);
    }
  }

  return r;
}

/**
 * @fn
 * Return nonterminals for the expression of this rule.
 * @brief Get nonterms
 * @return Vector of NTermID
 */
const std::vector<NTermID>& Rule::Nonterms() const {
  if (std::holds_alternative<PlainRule>(_rule)) {
    return std::get<PlainRule>(_rule).nonterms;

  } else {
    throw exceptions::not_implemented("Only PlainRule is supported", __FILE__,
                                      __LINE__);
  }
}

/**
 * @fn
 * Return the number of nonterminals in the expression of this rule.
 * @brief Get number of nonterminals
 * @return Number of nonterminals
 */
size_t Rule::NumberOfNonterms() const { return Nonterms().size(); }

/**
 * @fn
 * Return nonterminal ID of the symbol of this rule
 * @brief Get nonterminal
 * @return NTermID of this rule
 */
const NTermID& Rule::Nonterm() const {
  return std::visit([](auto& r) -> const NTermID& { return r.nonterm; }, _rule);
}

/**
 * @fn
 * Generate a random tree from this rule.
 * @brief Generate a tree for this rule
 * @param (tree) A reference to a tree to store the generated tree
 * @param (ctx) Context
 * @param (len) Maximum length of the tree to generate
 * @return Total size of the generated tree
 */
size_t Rule::Generate(Tree& tree, Context& ctx, size_t len) const {
  /* Calculate required length */
  size_t minimal_needed_len = 0;
  for (NTermID nt : Nonterms()) minimal_needed_len += ctx.GetMinLenForNT(nt);

  DEBUG_ASSERT(minimal_needed_len <= len);

  size_t remaining_len = len - minimal_needed_len;

  size_t total_size = 1;
  NodeID paren(tree.Size() - 1);

  /* Iterate over nonterminals */
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

    DEBUG_ASSERT(tree.rules().size() == tree.sizes().size());
    DEBUG_ASSERT(tree.paren().size() == tree.sizes().size());

    size_t offset = tree.Size();
    tree.rules().emplace_back(rule_or_custom);
    tree.sizes().emplace_back(0);
    tree.paren().emplace_back(0);

    size_t consumed_len =
        ctx.GetRule(rid).Generate(tree, ctx, cur_child_max_len - 1);
    tree.sizes()[offset] = consumed_len;
    tree.paren()[offset] = paren;

    DEBUG_ASSERT(consumed_len <= cur_child_max_len);
    DEBUG_ASSERT(consumed_len >= ctx.GetMinLenForNT(nonterms[i]));

    remaining_len += ctx.GetMinLenForNT(nonterms[i]);
    remaining_len -= consumed_len;
    total_size += consumed_len;
  }

  return total_size;
}

/**
 * @fn
 * Constructor of RuleChild from a terminal.
 * @brief Construct RuleChild from literal
 * @param (lit) Literal string
 *
 * @details This constructor takes a terminal symbol (literal).
 *          The type of this RuleChild becomes Term.
 */
RuleChild::RuleChild(const std::string& lit) { _rule_child = lit; }

/**
 * @fn
 * Constructor of RuleChild from a nonterminal.
 * @brief Construct RuleChild from nonterminal
 * @param (nt) Nonterminal symbol string
 * @param (ctx) Context
 *
 * @details This constructor takes a nonterminal symbol.
 *          The type of this RuleChild becomes NTerm.
 */
RuleChild::RuleChild(const std::string& nt, Context& ctx) {
  std::string nonterm = SplitNTDescription(nt);
  _rule_child = NTerm(ctx.AquireNTID(nonterm));
}

/**
 * @fn
 * Describe this RuleChild instance into a human-readable string.
 * @brief Describe RuleChild as string
 * @param (ctx) Context
 * @return Human-readable string
 */
std::string RuleChild::DebugShow(Context& ctx) const {
  if (std::holds_alternative<NTerm>(_rule_child)) {
    return ctx.NTIDToString(std::get<NTerm>(_rule_child));
  } else {
    return ShowBytes(std::get<Term>(_rule_child));
  }
}

/**
 * @fn
 * Parse the string representation of a nonterminal.
 * @brief Split nonterminal description
 * @param (nonterm) Nonterminal symbol
 * @throw exceptions::fuzzuf_runtime_error @p nonterm is an invalid symbol
 * @return Extracted nonterminal symbol
 *
 * @details This method parses the nonterminal string.
 *          For example, `{ABC:xyz}` is parsed into `ABC` and `xyz`.
 *          This method returns only the nonterminal symbol, `ABC`.
 */
std::string RuleChild::SplitNTDescription(const std::string& nonterm) const {
  std::smatch m;
  static std::regex SPLITTER(
      R"(^\{([A-Z][a-zA-Z_\-0-9]*)(?::([a-zA-Z_\-0-9]*))?\}$)");

  // Splits {A:a} or {A} into A and maybe a
  if (!std::regex_match(nonterm, m, SPLITTER)) {
    throw exceptions::fuzzuf_runtime_error(
        fuzzuf::utils::StrPrintf("Could not interpret Nonterminal %s. "
                                 "Nonterminal Descriptions need to match "
                                 "start with a capital letter and can only "
                                 "contain [a-zA-Z_-0-9]",
                                 nonterm.c_str()),
        __FILE__, __LINE__);
  }

  return m[1].str();
}

/**
 * @fn
 * Return RuleID of this RuleIDOrCustom.
 * @brief Get RuleID
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
 * Return data of this RuleIDOrCustom if it's a custom rule.
 * @brief Get data
 * @throw exceptions::fuzzuf_runtime_error The rule is not a custom rule.
 * @return Data of this RuleIDOrCustom
 */
const std::string& RuleIDOrCustom::Data() const {
  if (std::holds_alternative<RuleID>(_rule_id_or_custom)) {
    throw exceptions::fuzzuf_runtime_error("Cannot get data on a normal rule",
                                           __FILE__, __LINE__);
  } else {
    return std::get<Custom>(_rule_id_or_custom).second;
  }
}

/**
 * @fn
 * Describe this PlainRule into a human-readable string.
 * @brief Describe this PlainRule
 * @return Human-readable string
 */
std::string PlainRule::DebugShow(Context& ctx) const {
  std::string res;
  for (size_t i = 0; i < children.size(); i++) {
    res += children[i].DebugShow(ctx);
    if (i != children.size() - 1) res += ", ";
  }
  return ctx.NTIDToString(nonterm) + " => " + res;
}

/**
 * @fn
 * Escape some special and unprintable characters.
 * @brief Escape string
 * @return Escaped string
 *
 * @details This function escapes newlines (`\t`, `\r`, `\n`),
 *          backslash, quotes (`'`, `"`) by appending a backslash
 *          in front. It also escapes other unprintable characters
 *          into a hex representation like `\x9f`.
 */
std::string ShowBytes(const std::string& bs) {
  std::stringstream ss;
  for (size_t i = 0; i < bs.size(); i++) {
    char c = bs[i];
    if (0x20 <= c && c <= 0x7e) {
      ss << c;
    } else {
      switch (c) {
        case '\t':
          ss << "\\t";
          break;
        case '\r':
          ss << "\\r";
          break;
        case '\n':
          ss << "\\n";
          break;
        case '\'':
          ss << "\\'";
          break;
        case '"':
          ss << "\\\"";
          break;
        case '\\':
          ss << "\\\\";
          break;
        default:
          ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex
             << (uint8_t)c;
          break;
      }
    }
  }

  return ss.str();
}

}  // namespace fuzzuf::algorithm::nautilus::grammartec
