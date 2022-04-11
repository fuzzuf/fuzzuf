/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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

#include <unordered_map>
#include <any>
#include <string>
#include <iostream>
#include <cxxabi.h>

class Store {
public:
    ~Store();

    static Store& GetInstance();

    template<typename T>
    T Get(std::string key);

    template<typename T>
    void Set(std::string key, T val);

    bool Exists(std::string key);

private:
    Store();

    std::unordered_map<std::string, std::any> data;
};

template<typename T>
T Store::Get(std::string key) {
    try {
        return std::any_cast<T>(data[key]);
    }
    catch (std::bad_any_cast& e) {
        throw e;
    }
}

template<typename T>
void Store::Set(std::string key, T val) {
    data[key] = val;
}

#endif
