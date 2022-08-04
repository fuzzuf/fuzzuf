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

#include "fuzzuf/optimizer/store.hpp"

#include "fuzzuf/logger/logger.hpp"

namespace fuzzuf::optimizer {

Store::Store() {}
Store::~Store() {}

Store &Store::GetInstance() {
  static Store store;
  return store;
}

void OnKeyDoesntExist(const std::string &v) {
  ERROR("not found key '%s'", v.c_str());
}

void OnKeyAlreadyExists(const std::string &v) {
  ERROR("key '%s' already exists", v.c_str());
}

}  // namespace fuzzuf::optimizer
