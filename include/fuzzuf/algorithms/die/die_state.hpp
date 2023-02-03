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
 * @file die_state.hpp
 * @brief Global state for HierarFlow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <memory>

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/die/die_option.hpp"
#include "fuzzuf/algorithms/die/die_setting.hpp"
#include "fuzzuf/algorithms/die/die_testcase.hpp"
#include "fuzzuf/exceptions.hpp"

namespace fuzzuf::algorithm::die {

struct DIEState : public afl::AFLStateTemplate<DIETestcase> {
  explicit DIEState(std::shared_ptr<const DIESetting> setting,
                    std::shared_ptr<executor::AFLExecutorInterface> executor)
      : AFLStateTemplate<DIETestcase>(setting, executor, nullptr),
        setting(setting){};

  /* Override these methods to prevent mistakes during development */
  std::shared_ptr<DIETestcase> AddToQueue(const std::string&, const u8*, u32,
                                          bool) {
    using exceptions::fuzzuf_logic_error;
    throw fuzzuf_logic_error("AddToQueue is banned (DIE)", __FILE__, __LINE__);
  }
  bool SaveIfInteresting(const u8*, u32, feedback::InplaceMemoryFeedback&,
                         feedback::ExitStatusFeedback&) {
    using exceptions::fuzzuf_logic_error;
    throw fuzzuf_logic_error("SaveIfInteresting is banned (DIE)", __FILE__,
                             __LINE__);
  };

  /* We must call these instead of the methods above */
  std::shared_ptr<DIETestcase> AddToQueue(const std::string&, const u8*,
                                          u32,  // js file
                                          const std::string&, const u8*,
                                          u32,  // type file
                                          bool);
  bool SaveIfInteresting(const u8*, u32,  // js file
                         const u8*, u32,  // type file
                         feedback::InplaceMemoryFeedback&,
                         feedback::ExitStatusFeedback&);

  /* Override methods that call the methods above */
  void ReadTestcases(void);
  void PivotInputs(void);

  /* Other methods to override */
  void ShowStats(void);

  /* Setting from CLI */
  std::shared_ptr<const DIESetting> setting;
};

}  // namespace fuzzuf::algorithm::die
