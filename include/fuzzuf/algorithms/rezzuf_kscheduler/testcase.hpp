/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
#ifndef FUZZUF_INCLUDE_ALGORITHM_REZZUF_KSCHEDULER_TESTCASE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_REZZUF_KSCHEDULER_TESTCASE_HPP

#include <memory>
#include "fuzzuf/algorithms/rezzuf/rezzuf_testcase.hpp"
#include "fuzzuf/algorithms/rezzuf_kscheduler/option.hpp"
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"

namespace fuzzuf::algorithm::rezzuf_kscheduler {

struct Testcase : public rezzuf::RezzufTestcase {
  using Tag = afl::option::RezzufKSchedulerTag;

  Testcase(std::shared_ptr<exec_input::OnDiskExecInput> input) :
    rezzuf::RezzufTestcase( input ) {}
};

}  // namespace fuzzuf::algorithm::rezzuf_kscheduler

#endif
