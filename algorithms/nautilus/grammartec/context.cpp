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
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

void Context::Initialize(size_t max_len) {
  //CalcMinLen();
  //CalcNumOptions();
  _max_len = max_len + 2;
}

/*
Rule& GetRule(RuleID r) {
  return _rules[static_cast<size_t>(r)];
}
*/

NTermID Context::AquireNTID(const std::string& nt) {
  NTermID next_id(_nt_ids_to_name.size());

  NTermID id = _names_to_nt_id.find(nt) == _names_to_nt_id.end()
    ? (_names_to_nt_id[nt] = next_id) // not exists
    : _names_to_nt_id[nt];            // exists

  if (_nt_ids_to_name.find(id) == _nt_ids_to_name.end())
    _nt_ids_to_name[id] = nt;

  return id;
}

NTermID Context::NTID(const std::string& nt) {
  assert (_names_to_nt_id.find(nt) != _names_to_nt_id.end());
  return _names_to_nt_id[nt];
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
