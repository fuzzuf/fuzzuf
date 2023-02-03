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
/**
 * @file die_testcase.hpp
 * @brief Testcase of DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <memory>

#include "fuzzuf/algorithms/afl/afl_testcase.hpp"
#include "fuzzuf/algorithms/die/die_option.hpp"
#include "fuzzuf/exec_input/on_disk_exec_input.hpp"

namespace fuzzuf::algorithm::die {

struct DIETestcase : public afl::AFLTestcase {
  using Tag = option::DIETag;

  /* Override constructor to prevent mistakes during development */
  DIETestcase(std::shared_ptr<exec_input::OnDiskExecInput> input)
      : AFLTestcase(input) {
    using exceptions::fuzzuf_logic_error;
    throw fuzzuf_logic_error("DIETestcase(input) is banned (DIE)", __FILE__,
                             __LINE__);
  }

  /* We must call this instead of the method above */
  DIETestcase(std::shared_ptr<exec_input::OnDiskExecInput> input,
              std::shared_ptr<exec_input::OnDiskExecInput> input_type)
      : AFLTestcase(input),     // js file
        input_type(input_type)  // type file
        {};
  ~DIETestcase(){};

  std::shared_ptr<exec_input::OnDiskExecInput> input_type;  // type file
};

}  // namespace fuzzuf::algorithm::die
