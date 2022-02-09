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
 * @file context.cpp
 * @brief Class for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <algorithm>
#include <iostream>
#include <limits>
#include <optional>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

/**
 * @fn
 * @brief Initialize this context
 * @param (max_len) [TODO]
 */
void Context::Initialize(size_t max_len) {
  CalcMinLen();
  CalcNumOptions();
  _max_len = max_len + 2;
}

/**
 * @fn
 * @brief Get rule by RuleID
 * @param (r) RuleID
 * @return Rule referenced by RuleID
 */
const Rule& Context::GetRule(const RuleID& r) const {
  return _rules.at(static_cast<size_t>(r));
}

/**
 * @fn
 * @brief Get nonterminal ID by RuleIDOrCustom
 * @param (r) RuleIDOrCustom
 * @return Nonterminal ID
 */
const NTermID& Context::GetNT(const RuleIDOrCustom& r) const {
  return GetRule(r.ID()).Nonterm();
}

/**
 * @fn
 * @brief Get number of children by RuleIDOrCustom
 * @param (r) RuleIDOrCustom
 * @return Number of children
 */
size_t Context::GetNumChildren(const RuleIDOrCustom& r) const {
  return GetRule(r.ID()).NumberOfNonterms();
}

/**
 * @fn
 * @brief Describe NTermID as string
 * @param (nt) NTermID
 * @return String describing NTermID
 */
const std::string& Context::NTIDToString(const NTermID& nt) const {
  return _nt_ids_to_name.at(nt);
}

/**
 * @fn
 * @brief Get minimum length for nonterminal
 * @param (nt) Nonterminal symbol
 * @return Minimum length
 */
size_t Context::GetMinLenForNT(const NTermID& nt) const {
  return _nts_to_min_size.at(nt);
}

/**
 * @fn
 * @brief Register new NTID
 * @param (nt) Nonterminal symbol
 * @return Registered NTermID
 */
NTermID Context::AquireNTID(const std::string& nt) {
  NTermID next_id(_nt_ids_to_name.size()); // New NTermID

  NTermID& id = _names_to_nt_id.find(nt) == _names_to_nt_id.end()
    ? (_names_to_nt_id[nt] = next_id) // not exists
    : _names_to_nt_id[nt];            // exists

  if (_nt_ids_to_name.find(id) == _nt_ids_to_name.end())
    _nt_ids_to_name[id] = nt;

  return id;
}

/**
 * @fn
 * @brief Lookup NTermID by nonterminal symbol
 * @param (nt) Nonterminal symbol
 * @return NTermID of nt (An exception thrown if nt not found)
 */
const NTermID& Context::NTID(const std::string& nt) const {
  return _names_to_nt_id.at(nt);
}

/**
 * @fn
 * @brief Add a new rule to this context
 * @param (nt) Nonterminal symbol
 * @param (format) Format string
 * @return Registered RuleID
 */
RuleID Context::AddRule(const std::string& nt, const std::string& format) {
  RuleID rid(_rules.size()); // New rule ID
  const NTermID& ntid = AquireNTID(nt);

  _rules.emplace_back(*this, nt, format);

  // Register this rule
  if (_nts_to_rules.find(ntid) == _nts_to_rules.end())
    _nts_to_rules[ntid] = {};
  _nts_to_rules[ntid].emplace_back(rid);

  return rid;
}

/**
 * @fn
 * @brief Calculate number of options for a rule
 * @param (r) RuleID
 * @return Number of options
 */
size_t Context::CalcNumOptionsForRule(const RuleID& r) const {
  size_t res = 1;

  for (const NTermID& nt_id: GetRule(r).Nonterms()) {
    size_t v = _nts_to_num_options.find(nt_id) == _nts_to_num_options.end()
      ? 1
      : _nts_to_num_options.at(nt_id);
    if (__builtin_mul_overflow(res, v, &res)) {
      /* Saturate instead of overflow */
      res = std::numeric_limits<size_t>::max();
    }
  }

  return res;
}

/**
 * @fn
 * @brief Calculate number of options
 */
void Context::CalcNumOptions() {
  for (auto& elem: _nts_to_rules) {
    if (_nts_to_num_options.find(elem.first) == _nts_to_num_options.end()) {
      _nts_to_num_options[elem.first] = _rules.size();
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
 * @brief Calculate minimum length for a rule
 * @param (r) RuleID
 * @return Minimum length (nullopt on failure)
 */
std::optional<size_t> Context::CalcMinLenForRule(const RuleID& r) const {
  size_t res = 1;

  for (const NTermID& nt_id: GetRule(r).Nonterms()) {
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
 * @brief Sort rules referenced by NTermID
 */
void Context::CalcRuleOrder() {
  for (auto& elem: _nts_to_rules) {
    std::vector<RuleID>& rules = elem.second;
    std::sort(rules.begin(), rules.end(),
              [this](RuleID& r1, RuleID& r2) {
                return _rules_to_min_size.at(r1) < _rules_to_min_size.at(r2);
              });
  }
}

/**
 * @fn
 * @brief Calculate minimum length
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
      for (auto it = unknown_rules.crbegin();
           it != unknown_rules.crend();
           ++it) {
        const RuleID& rule = *it;

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

          /* Be careful base of reverse iterator is off by one */
          unknown_rules.erase(--(it.base()));
        }
      }

      if (last_len == unknown_rules.size()) {
        std::cerr << "Found unproductive rules: (missing base/non recursive case?)" << std::endl;
        for (RuleID& r: unknown_rules) {
          std::cerr << GetRule(r).DebugShow(*this) << std::endl;
        }
        throw exceptions::fuzzuf_runtime_error(
          "Broken grammar", __FILE__, __LINE__
        );
      }
    }
  } while (something_changed);

  CalcRuleOrder();
}

/**
 * @fn
 * @brief Get random length
 * @param (number_of_children) Number of children rules
 * @param (total_remaining_len) Remaining length
 * @return Random length
 */
size_t Context::GetRandomLen(size_t number_of_children,
                             size_t total_remaining_len) const {
  ssize_t res = total_remaining_len;
  ssize_t iters = number_of_children - 1;

  for (ssize_t i = 0; i < iters; i++) {
    ssize_t proposal = utils::random::Random<ssize_t>(
      0, total_remaining_len + 1
    );
    if (proposal < res)
      res = proposal;
  }

  return res;
}

/**
 * @fn
 * @brief Get list of applicable rules
 * @param (max_len) Maximum length for rule
 * @param (nt) Nonterminal symbol ID
 * @param (p_include_short_rules) Threshold to select rule (0 to 100)
 * @return Vector of rule IDs
 */
std::vector<RuleID> Context::GetApplicableRules(
  size_t max_len,
  const NTermID& nt,
  size_t p_include_short_rules
) const {
  std::vector<RuleID> res;

  for (const RuleID& rid: _nts_to_rules.at(nt)) {
    if (_rules_to_min_size.at(rid) > max_len) break;
    if (_rules_to_num_options.at(rid) > 1
        || utils::random::Random<size_t>(0, 99) <= p_include_short_rules)
      res.emplace_back(rid);
  }

  return res;
}

/**
 * @fn
 * @brief Get random rule for a nonterminal symbol
 * @param (nt) Nonterminal symbol ID
 * @param (max_len) Maximum length for rule
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

  std::vector<RuleID> applicable_rules = GetApplicableRules(
    max_len, nt, p_include_short_rules
  );
  if (applicable_rules.size() > 0) {
    return fuzzuf::utils::random::Choose(applicable_rules);
  }

  applicable_rules = GetApplicableRules(max_len, nt, 100);
  if (applicable_rules.size() > 0) {
    return fuzzuf::utils::random::Choose(applicable_rules);
  }

  throw exceptions::fuzzuf_runtime_error(
    Util::StrPrintf("There is no way to derive %s within %d steps",
                    _nt_ids_to_name.at(nt).c_str(), max_len),
    __FILE__, __LINE__
  );
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
