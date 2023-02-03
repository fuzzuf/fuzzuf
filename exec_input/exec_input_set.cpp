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
#include "fuzzuf/exec_input/exec_input_set.hpp"

namespace fuzzuf::exec_input {

ExecInputSet::ExecInputSet() {}

ExecInputSet::~ExecInputSet() {}

size_t ExecInputSet::size(void) { return elems.size(); }

utils::NullableRef<ExecInput> ExecInputSet::get_ref(u64 id) {
  auto itr = elems.find(id);
  if (itr == elems.end()) return std::nullopt;
  return *itr->second;
}

std::shared_ptr<ExecInput> ExecInputSet::get_shared(u64 id) {
  auto itr = elems.find(id);
  if (itr == elems.end()) return nullptr;
  return itr->second;
}

void ExecInputSet::erase(u64 id) {
  auto itr = elems.find(id);
  if (itr == elems.end()) return;

  elems.erase(itr);
}

std::vector<u64> ExecInputSet::get_ids(void) {
  std::vector<u64> ids;
  for (auto& itr : elems) {
    ids.emplace_back(itr.first);
  }
  return ids;
}

}  // namespace fuzzuf::exec_input
