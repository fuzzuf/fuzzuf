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

#ifndef FUZZUF_INCLUDE_OPTIMIZER_STORE_HPP
#define FUZZUF_INCLUDE_OPTIMIZER_STORE_HPP

#include <any>
#include <string>
#include <unordered_map>

namespace fuzzuf::optimizer {

/**
 * @struct StoreKey
 * @details This class is used as a key in Store.
 * If you want to add some value in Store, you should declare a new variable of
 * StoreKey, and use it as the identifier of the value.
 */
template <class Type>
struct StoreKey {
  std::string name;
};

/**
 * @class Store
 * @brief Key-value store that bridges between fuzzers and optimizers
 * @note This class is implemented with the singleton pattern
 * because we want to share Store instance between fuzzers and optimizers with
 *no difficulty. This design gets devastating if we would like to have mutiple
 *fuzzer instances in a single process/thread, but we currently assume that such
 *situations don't happen.
 **/
class Store {
 public:
  ~Store();

  static Store& GetInstance();

  template <typename Type>
  void InitKey(const StoreKey<Type>& key, bool initialize_just_once = false);

  template <typename Type>
  void InitKey(const StoreKey<Type>& key, Type val,
               bool initialize_just_once = false);

  template <typename Type>
  Type Get(const StoreKey<Type>& key, bool assert = false);

  template <typename Type>
  Type& GetMutRef(const StoreKey<Type>& key, bool assert = false);

  template <typename Type>
  void Set(const StoreKey<Type>& key, Type val);

  template <typename Type>
  bool Exists(const StoreKey<Type>& key);

 private:
  Store();

  std::unordered_map<std::string, std::any> data;
};

void OnKeyDoesntExist(const std::string&);
void OnKeyAlreadyExists(const std::string&);

template <typename Type>
void Store::InitKey(const StoreKey<Type>& key, bool initialize_just_once) {
  if (initialize_just_once && Exists(key)) {
    OnKeyAlreadyExists(key.name);
  }
  data[key.name] = Type();
}

template <typename Type>
void Store::InitKey(const StoreKey<Type>& key, Type val,
                    bool initialize_just_once) {
  if (initialize_just_once && Exists(key)) {
    OnKeyAlreadyExists(key.name);
  }
  data[key.name] = val;
}

template <typename Type>
Type Store::Get(const StoreKey<Type>& key, bool assert) {
  // may throw std::bad_any_cast
  auto it = data.find(key.name);

  if (assert && it == data.end()) {
    OnKeyDoesntExist(key.name);
  }

  return std::any_cast<Type>(it->second);
}

template <typename Type>
Type& Store::GetMutRef(const StoreKey<Type>& key, bool assert) {
  // may throw std::bad_any_cast
  auto it = data.find(key.name);

  if (assert && it == data.end()) {
    OnKeyDoesntExist(key.name);
  }

  return std::any_cast<Type&>(it->second);
}

template <typename Type>
void Store::Set(const StoreKey<Type>& key, Type val) {
  data[key.name] = val;
}

template <typename Type>
bool Store::Exists(const StoreKey<Type>& key) {
  return data.find(key.name) != data.end();
}

}  // namespace fuzzuf::optimizer

#endif
