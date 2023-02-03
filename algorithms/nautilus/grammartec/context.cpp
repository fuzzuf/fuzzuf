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
 * @file context.cpp
 * @brief Context class for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 *
 * @details This function defines Context class.
 *          Context keeps every grammar rules and can translate
 *          nonterminal IDs, rule IDs and so on mutually.
 *          It also has an interface to generate a random tree
 *          by nonterminal ID or Rule ID.
 */
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"

#include <algorithm>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

/**
 * @fn
 * Prepare this context to be used.
 * @brief Initialize this context
 * @param (max_len) Maximum length of the tree to be generated.
 *
 * @details This method calculates the minimum required length of tree
 *          and the number of options.
 *          It must be called after you add every rule by AddRule method.
 */
void Context::Initialize(size_t max_len) {
  CalcMinLen();
  CalcNumOptions();
  _max_len = max_len + 2;
}

/**
 * @fn
 * Get the Rule instance referenced by RuleID.
 * @brief Get rule
 * @param (r) RuleID
 * @throw std::out_of_range Rule ID is invalid
 * @return Rule referenced by @p r
 */
const Rule& Context::GetRule(const RuleID& r) const {
  return _rules.at(static_cast<size_t>(r));
}

/**
 * @fn
 * Get the NTermID referenced by RuleIDOrCustom.
 * @brief Get nonterminal
 * @param (r) RuleIDOrCustom
 * @throw std::out_of_range Rule ID is invalid
 * @return ID of the nonterminal referenced by @p r
 */
const NTermID& Context::GetNT(const RuleIDOrCustom& r) const {
  return GetRule(r.ID()).Nonterm();
}

/**
 * @fn
 * Get the number of children of a rule referenced by RuleIDOrCustom.
 * @brief Get the number of rule children
 * @param (r) RuleIDOrCustom
 * @throw std::out_of_range Rule ID is invalid
 * @return The number of children of the rule referenced by @p r
 */
size_t Context::GetNumChildren(const RuleIDOrCustom& r) const {
  return GetRule(r.ID()).NumberOfNonterms();
}

/**
 * @fn
 * Return the string representation of a nonterminal.
 * @brief Describe a nonterminal as a string
 * @param (nt) Nonterminal ID
 * @throw std::out_of_range Nonterminal ID is invalid
 * @return String corresponding to @p nt
 */
const std::string& Context::NTIDToString(const NTermID& nt) const {
  return _nt_ids_to_name.at(nt);
}

/**
 * @fn
 * Get the minimum length of a nonterminal ID
 * @brief Get minimum length for nonterminal
 * @param (nt) Nonterminal ID
 * throw std::out_of_range Nonterminal ID is invalid
 * @return Minimum length for @p nt
 */
size_t Context::GetMinLenForNT(const NTermID& nt) const {
  return _nts_to_min_size.at(nt);
}

/**
 * @fn
 * Register a new nonterminal symbol and get its ID
 * @brief Register a new nonterminal symbol
 * @param (nt) String of a nonterminal symbol
 * @return Nonterminal ID of @p nt
 *
 * @details This method looks up a nonterminal symbol.
 *          If there exists one, the corresponding nonterminal ID
 *          is returned.
 *          Otherwise this method registers the new nonterminal symbol
 *          and returns a new ID.
 */
NTermID Context::AquireNTID(const std::string& nt) {
  NTermID next_id(_nt_ids_to_name.size());  // New NTermID

  NTermID& id = _names_to_nt_id.find(nt) == _names_to_nt_id.end()
                    ? (_names_to_nt_id[nt] = next_id)  // not exists
                    : _names_to_nt_id[nt];             // exists

  if (_nt_ids_to_name.find(id) == _nt_ids_to_name.end())
    _nt_ids_to_name[id] = nt;

  return id;
}

/**
 * @fn
 * Return nonterminal ID referenced by a nonterminal symbol
 * @brief Lookup NTermID by nonterminal symbol
 * @param (nt) String of a nonterminal symbol
 * @throw std::out_of_range Nonterminal symbol does not exist
 * @return Nonterminal referenced by @p nt
 */
const NTermID& Context::NTID(const std::string& nt) const {
  return _names_to_nt_id.at(nt);
}

/**
 * @fn
 * Add a new plain rule to this context.
 * @brief Add a new rule
 * @param (nt) Nonterminal symbol
 * @param (format) Format string (expression)
 * @return Registered rule ID
 */
RuleID Context::AddRule(const std::string& nt, const std::string& format) {
  RuleID rid(_rules.size());  // New rule ID
  const NTermID& ntid = AquireNTID(nt);

  /* Register this rule */
  _rules.emplace_back(*this, nt, format);

  if (_nts_to_rules.find(ntid) == _nts_to_rules.end()) _nts_to_rules[ntid] = {};
  _nts_to_rules[ntid].emplace_back(rid);

  return rid;
}

/**
 * @fn
 * Calculate the number of options for a rule.
 * @brief Calculate number of options
 * @param (r) RuleID
 * @return Number of options for @p r
 */
size_t Context::CalcNumOptionsForRule(const RuleID& r) const {
  size_t res = 1;

  for (const NTermID& nt_id : GetRule(r).Nonterms()) {
    size_t v = _nts_to_num_options.find(nt_id) == _nts_to_num_options.end()
                   ? 1
                   : _nts_to_num_options.at(nt_id);

    if (__builtin_mul_overflow(res, v, &res)) {
      /* Saturate instead of overflow */
      res = std::numeric_limits<size_t>::max();
      break;
    }
  }

  return res;
}

/**
 * @fn
 * @brief Calculate number of options
 */
void Context::CalcNumOptions() {
  for (auto& elem : _nts_to_rules) {
    if (_nts_to_num_options.find(elem.first) == _nts_to_num_options.end()) {
      _nts_to_num_options[elem.first] = elem.second.size();
    }
  }

  bool something_changed;
  do {
    something_changed = false;

    for (size_t i = 0; i < _rules.size(); i++) {
      RuleID rid(i);
      size_t num = CalcNumOptionsForRule(rid);
      const NTermID& nt = GetRule(rid).Nonterm();

      if (_nts_to_num_options.find(nt) == _nts_to_num_options.end())
        _nts_to_num_options[nt] = num;

      /* Update maximum number */
      if (_nts_to_num_options[nt] < num) {
        _nts_to_num_options[nt] = num;
        something_changed = true;
      }

      _rules_to_num_options[rid] = num;
    }
  } while (something_changed);
}

/**
 * @fn
 * Calculate the minimum length for a rule
 * @brief Calculate minimum length
 * @param (r) RuleID
 * @return Minimum length (nullopt on failure)
 */
std::optional<size_t> Context::CalcMinLenForRule(const RuleID& r) const {
  size_t res = 1;

  for (const NTermID& nt_id : GetRule(r).Nonterms()) {
    if (_nts_to_min_size.find(nt_id) == _nts_to_min_size.end()) {
      return std::nullopt;

    } else {
      res += _nts_to_min_size.at(nt_id);
    }
  }

  return res;
}

/**
 * @fn
 * @brief Sort rules
 */
void Context::CalcRuleOrder() {
  for (auto& elem : _nts_to_rules) {
    std::vector<RuleID>& rules = elem.second;
    std::sort(rules.begin(), rules.end(), [this](RuleID& r1, RuleID& r2) {
      return _rules_to_min_size.at(r1) < _rules_to_min_size.at(r2);
    });
  }
}

/**
 * @fn
 * @brief Calculate minimum length
 * @throw exceptions::fuzzuf_runtime_error Grammar is invalid
 */
void Context::CalcMinLen() {
  bool something_changed;

  do {
    std::vector<RuleID> unknown_rules;
    unknown_rules.reserve(_rules.size());
    for (size_t i = 0; i < _rules.size(); i++) {
      unknown_rules.emplace_back(i);
    }
    something_changed = false;

    while (unknown_rules.size()) {
      size_t last_len = unknown_rules.size();

      /* Remove every rule with known minimum length */
      auto r = std::remove_if(
          unknown_rules.begin(), unknown_rules.end(),
          [this, &something_changed](const RuleID& rule) {
            if (std::optional<size_t> min = CalcMinLenForRule(rule)) {
              const NTermID& nt = GetRule(rule).Nonterm();

              if (_nts_to_min_size.find(nt) == _nts_to_min_size.end())
                _nts_to_min_size[nt] = min.value();

              if (_nts_to_min_size[nt] > min.value()) {
                /* Update minimum value */
                _nts_to_min_size[nt] = min.value();
                something_changed = true;
              }

              _rules_to_min_size[rule] = min.value();
              return true;
            }

            return false;
          });
      unknown_rules.erase(r, unknown_rules.end());

      if (last_len == unknown_rules.size()) {
        std::cerr
            << "Found unproductive rules: (missing base/non recursive case?)"
            << std::endl;
        for (RuleID& r : unknown_rules) {
          std::cerr << GetRule(r).DebugShow(*this) << std::endl;
        }
        throw exceptions::fuzzuf_runtime_error("Broken grammar", __FILE__,
                                               __LINE__);
      }
    }
  } while (something_changed);

  CalcRuleOrder();
}

/**
 * @fn
 * Check if the number of rules for a nonterminal ID is more than 1.
 * @brief Check if a nonterminal has multiple rules
 * @throw std::out_of_range Nonterminal ID is invalid
 * @return True if nonterminal has multiple possibilities, otherwise false
 */
bool Context::CheckIfNTermHasMultiplePossibilities(const NTermID& nt) const {
  return GetRulesForNT(nt).size() > 1;
}

/**
 * @fn
 * Get a random length by the number of rule children and maximum length.
 * @brief Get a random length
 * @param (number_of_children) Number of children rules
 * @param (total_remaining_len) Remaining length
 * @return Random length
 */
size_t Context::GetRandomLen(size_t number_of_children,
                             size_t total_remaining_len) const {
  ssize_t res = total_remaining_len;
  ssize_t iters = number_of_children - 1;

  for (ssize_t i = 0; i < iters; i++) {
    ssize_t proposal =
        utils::random::Random<ssize_t>(0, total_remaining_len + 1);
    if (proposal < res) res = proposal;
  }

  return res;
}

/**
 * @fn
 * Get a list of applicable rules for a given constraints.
 * @brief Get list of applicable rules
 * @param (max_len) Maximum length for rule
 * @param (nt) Nonterminal symbol ID
 * @param (p_include_short_rules) Threshold to select rule (0 to 100)
 * @return Vector of rule IDs
 */
std::vector<RuleID> Context::GetApplicableRules(
    size_t max_len, const NTermID& nt, size_t p_include_short_rules) const {
  std::vector<RuleID> res;

  for (const RuleID& rid : _nts_to_rules.at(nt)) {
    if (_rules_to_min_size.at(rid) > max_len) break;
    if (_rules_to_num_options.at(rid) > 1 ||
        utils::random::Random<size_t>(0, 99) <= p_include_short_rules)
      res.emplace_back(rid);
  }

  return res;
}

/**
 * @fn
 * Get a random rule for a nonterminal ID and maximum length.
 * @brief Get a random rule for a nonterminal ID
 * @param (nt) Nonterminal symbol ID
 * @param (max_len) Maximum length for rule
 * @throw exceptions::fuzzuf_runtime_error No rule is applicable
 * @return Selected rule ID
 */
RuleID Context::GetRandomRuleForNT(const NTermID& nt, size_t max_len) const {
  size_t p_include_short_rules;

  // TODO: Is the original implementation correct?
  if (_nts_to_num_options.at(nt) < 10) {
    p_include_short_rules = 100 * 0;
  } else if (max_len > 100) {
    p_include_short_rules = 2 * 0;
  } else if (max_len > 20) {
    p_include_short_rules = 50 * 0;
  } else {
    p_include_short_rules = 100 * 0;
  }

  std::vector<RuleID> applicable_rules =
      GetApplicableRules(max_len, nt, p_include_short_rules);
  if (applicable_rules.size() > 0) {
    return fuzzuf::utils::random::Choose(applicable_rules);
  }

  applicable_rules = GetApplicableRules(max_len, nt, 100);
  if (applicable_rules.size() > 0) {
    return fuzzuf::utils::random::Choose(applicable_rules);
  }

  throw exceptions::fuzzuf_runtime_error(
      fuzzuf::utils::StrPrintf("There is no way to derive %s within %d steps",
                               _nt_ids_to_name.at(nt).c_str(), max_len),
      __FILE__, __LINE__);
}

/**
 * @fn
 * @brief Get random length for a rule
 * @param (rule_id) Rule ID (not used)
 * @return Length
 */
size_t Context::GetRandomLenForRuleID(const RuleID&) const {
  return _max_len;  // TODO: this should be random
}

/**
 * @fn
 * @brief Get random length for a nonterminal
 * @param (nt) Nonterminal symbol ID (not used)
 * @return Length
 */
size_t Context::GetRandomLenForNT(const NTermID&) const {
  return _max_len;  // TODO: this should be random
}

/**
 * @fn
 * Get the list of rules referenced by a nonterminal ID.
 * @brief Get rules for a nonterminal ID
 * @param (nt) Nonterminal symbol ID
 * @throw std::out_of_range Nonterminal ID is invalid
 * @return Vector of rule IDs
 */
const std::vector<RuleID>& Context::GetRulesForNT(const NTermID& nt) const {
  return _nts_to_rules.at(nt);
}

/**
 * @fn
 * Generate a random tree by a nonterminal ID and maximum length.
 * @brief Generate a random tree by nonterminal
 * @param (nt) Nonterminal symbol ID
 * @param (max_len) Maximum length of the tree to be generated
 * @return Generated tree
 */
Tree Context::GenerateTreeFromNT(const NTermID& nt, size_t max_len) {
  return GenerateTreeFromRule(GetRandomRuleForNT(nt, max_len), max_len - 1);
}

/**
 * @fn
 * Generate a random tree by a rule and length.
 * @brief Generate a tree from rule
 * @param (r) Rule ID
 * @param (len) Length of the tree to be generated
 * @return Generated tree
 */
Tree Context::GenerateTreeFromRule(const RuleID& r, size_t len) {
  Tree tree({}, *this);
  tree.GenerateFromRule(r, len, *this);
  return tree;
}

}  // namespace fuzzuf::algorithm::nautilus::grammartec
