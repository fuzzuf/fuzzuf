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
#pragma once

#include <memory>
#include <unordered_map>

#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/feedback/persistent_memory_feedback.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/python/python_setting.hpp"
#include "fuzzuf/python/python_testcase.hpp"

namespace fuzzuf::bindings::python {

// We need this only for Mutator.
struct PythonTag {};

struct PythonState {
  explicit PythonState(const PythonSetting &setting);
  ~PythonState();

  const PythonSetting &setting;
  exec_input::ExecInputSet input_set;
  std::unordered_map<u64, std::unique_ptr<PythonTestcase>> test_set;
  std::unique_ptr<fuzzuf::mutator::Mutator<PythonTag>> mutator;
};

}  // namespace fuzzuf::bindings::python
