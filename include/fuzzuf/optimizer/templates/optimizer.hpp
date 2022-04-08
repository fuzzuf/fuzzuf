#pragma once

#include "fuzzuf/optimizer/optimizer.hpp"

template<typename T>
Optimizer<T>::Optimizer() {

}

template<typename T>
Optimizer<T>::Optimizer(std::function<T()> f) :
    logic(f)
{
}

template<typename T>
T Optimizer<T>::CalcValue() {
    return logic();
}