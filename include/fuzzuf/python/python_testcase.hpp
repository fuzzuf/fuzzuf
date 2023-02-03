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

#include "fuzzuf/exec_input/on_memory_exec_input.hpp"
#include "fuzzuf/feedback/persistent_memory_feedback.hpp"

namespace fuzzuf::bindings::python {

struct PythonTestcase {
  explicit PythonTestcase(std::shared_ptr<exec_input::OnMemoryExecInput> input,
                          feedback::PersistentMemoryFeedback &&afl_feed,
                          feedback::PersistentMemoryFeedback &&bb_feed);
  ~PythonTestcase();

  std::shared_ptr<exec_input::OnMemoryExecInput> input;
  feedback::PersistentMemoryFeedback afl_feed;
  feedback::PersistentMemoryFeedback bb_feed;
};

}  // namespace fuzzuf::bindings::python
