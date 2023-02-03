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

#include "fuzzuf/algorithms/afl_symcc/fuzzer.hpp"

#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/utils/get_external_seeds.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/sha1.hpp"
#include "fuzzuf/utils/vfs/read_once.hpp"

namespace fuzzuf::algorithm::afl_symcc {
void AFLSymCCFuzzer::OneLoop(void) {
  afl->OneLoop();
  if (!ShouldEnd() && afl->GetState().sync_external_queue) {
    if (afl->GetState().sync_interval_cnt++ %
        afl::option::GetSyncInterval<afl::AFLState>(afl->GetState())) {
      SyncFuzzers();
    }
  }
  if (!ShouldEnd()) {
    ++cycle;
    if (options.symcc_freq && cycle == options.symcc_freq) {
      cycle = 0u;
      RunSymCC();
    }
  }
}
void AFLSymCCFuzzer::SyncFuzzers() {
  for (const auto &seed :
       utils::GetExternalSeeds(afl->GetState().setting->out_dir.parent_path(),
                               afl->GetState().sync_id, true)) {
    feedback::ExitStatusFeedback exit_status;
    feedback::InplaceMemoryFeedback inp_feed =
        afl->GetState().RunExecutorWithClassifyCounts(
            &*seed.begin(), std::distance(seed.begin(), seed.end()),
            exit_status);
    if (exit_status.exit_reason != feedback::PUTExitReasonType::FAULT_TMOUT) {
      if (afl->GetState().SaveIfInteresting(
              &*seed.begin(), std::distance(seed.begin(), seed.end()), inp_feed,
              exit_status)) {
        afl->GetState().queued_discovered++;
      }
    }
  }
}
void AFLSymCCFuzzer::RunSymCC() {
  auto input = afl->GetInput();
  {
    const std::vector<unsigned char> temp(input.begin(), input.end());
    executor->Run(temp.data(), temp.size());
  }
  auto files_ =
      (executor->Filesystem() | fuzzuf::utils::vfs::adaptor::read_once)
          .MmapAll();
  for (auto &v : files_) {
    const std::vector<unsigned char> temp(v.second.begin(), v.second.end());
    const auto hash = utils::ToSerializedSha1(temp);
    /*
     * Since SymCC doesn't care known paths, multiple executions typically
     * generate tons of same input values. To prevent inserting many same
     * inputs to case_queue, this filteres already inserted values.
     */
    if (existing.find(hash) == existing.end()) {
      existing.insert(existing.end(), hash);
      afl->AddToQueue(temp.data(), temp.size());
    }
  }
}
}  // namespace fuzzuf::algorithm::afl_symcc
