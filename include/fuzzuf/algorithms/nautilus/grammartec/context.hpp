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
 * @file context.hpp
 * @brief Class for context-free grammar
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

class Rule;

class Context {
public:
  Context() : _max_len(0) {}

  void Initialize(size_t max_len);
  Rule& GetRule(RuleID r);
  std::string NTIDToString(NTermID nt);
  size_t GetMinLenForNT(NTermID nt);

  NTermID AquireNTID(const std::string& nt);
  NTermID NTID(const std::string& nt);

  RuleID AddRule(const std::string& nt, const std::string& format);

  size_t CalcNumOptionsForRule(RuleID r);
  void CalcNumOptions();
  std::optional<size_t> CalcMinLenForRule(RuleID r);
  void CalcRuleOrder();
  void CalcMinLen();

private:
  std::vector<Rule> _rules;
  std::unordered_map<NTermID, std::vector<RuleID>> _nts_to_rules;
  std::unordered_map<NTermID, std::string> _nt_ids_to_name;
  std::unordered_map<std::string, NTermID> _names_to_nt_id;
  std::unordered_map<RuleID, size_t> _rules_to_min_size;
  std::unordered_map<NTermID, size_t> _nts_to_min_size;
  std::unordered_map<RuleID, size_t> _rules_to_num_options;
  std::unordered_map<NTermID, size_t> _nts_to_num_options;
  size_t _max_len;
};

} // namespace fuzzuf::algorithms::nautilus::grammartec
