#pragma once

#include <unordered_map>
#include <any>
#include <string>
#include <iostream>
#include <cxxabi.h>

class Store {
public:
    Store();
    ~Store();

    template<typename T>
    T get(std::string key);

    template<typename T>
    void set(std::string key, T val);

    bool exists(std::string key);

private:
    static Store instance;
    std::unordered_map<std::string, std::any> data;
};


Store::Store() {};
Store::~Store() {};

template<typename T>
T Store::get(std::string key) {
    try {
        return std::any_cast<T>(data[key]);
    }
    catch (std::bad_any_cast& e) {
        throw e;
    }
}

template<typename T>
void Store::set(std::string key, T val) {
    data[key] = val;
}

bool Store::exists(std::string key) {
    return data.find(key) != data.end();
}
