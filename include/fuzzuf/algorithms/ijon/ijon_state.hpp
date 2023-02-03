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

#ifndef FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_IJON_IJON_STATE_HPP

#include <memory>
#include <vector>

#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/ijon/ijon_option.hpp"
#include "fuzzuf/algorithms/ijon/ijon_testcase.hpp"
#include "fuzzuf/exec_input/exec_input_set.hpp"
#include "fuzzuf/executor/ijon_executor_interface.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/optimizer/havoc_optimizer.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::ijon {

/**
 * @struct
 * expresses the internal state of IJON.
 * It inherits from AFLStateTemplate to be compatible with AFLState.
 * The lifetime for an instance of this class must be longer than that of
 * HierarFlow.
 */
struct IJONState : public afl::AFLStateTemplate<IJONTestcase> {
  explicit IJONState(
      std::shared_ptr<const afl::AFLSetting> setting,
      std::shared_ptr<executor::IJONExecutorInterface> executor,
      std::unique_ptr<optimizer::HavocOptimizer>&& havoc_optimizer);
  ~IJONState();

  IJONState(const IJONState&) = delete;
  IJONState& operator=(const IJONState&) = delete;

  std::shared_ptr<executor::IJONExecutorInterface> ijon_executor;

  std::vector<u64> max_map =
      std::vector<u64>(option::GetMaxMapSize<option::IJONTag>());
  // Instead of
  //    ijon_input_info* infos[MAXMAP_SIZE];
  //    size_t num_entries;
  // define the following vectors.
  // Corresponding code of original IJON implementation:
  // https://github.com/RUB-SysSec/ijon/blob/4cb8ae04d/afl-ijon-min.h#L16-L17
  std::vector<std::shared_ptr<exec_input::OnDiskExecInput>> all_inputs;
  std::vector<std::shared_ptr<exec_input::OnDiskExecInput>> nonempty_inputs;

  size_t num_updates = 0;
  fs::path max_dir;
  u32 old_current_entry = 0u;
  bool current_entry_is_swapped = false;
};

}  // namespace fuzzuf::algorithm::ijon

#endif
