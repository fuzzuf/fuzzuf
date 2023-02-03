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
 * @file nautilus_state.hpp
 * @brief Global state used for Nautilus during hieraflow loop
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_STATE_HPP

#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "fuzzuf/algorithms/nautilus/fuzzer/queue.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/setting.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/mutator.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/executor/afl_executor_interface.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

using namespace fuzzuf::algorithm::nautilus::grammartec;

enum ExecutionReason { Havoc, HavocRec, Min, MinRec, Splice, Det, Gen };

/* Shared global state */
struct NautilusState {
  explicit NautilusState(
      std::shared_ptr<const NautilusSetting> setting,
      std::shared_ptr<executor::AFLExecutorInterface> executor);

  bool RunOnWithDedup(const TreeLike& tree, ExecutionReason exec_reason,
                      Context& ctx);
  void RunOnWithoutDedup(const TreeLike& tree, ExecutionReason exec_reason,
                         Context& ctx);
  void RunOn(std::string& code, const TreeLike& tree,
             ExecutionReason exec_reason, Context& ctx);
  u64 ExecRaw(const std::string& code);
  void CheckForDeterministicBehavior(const std::vector<uint8_t>& old_bitmap,
                                     std::vector<size_t>& new_bits,
                                     const std::string& code);

  bool HasBits(const TreeLike& tree, std::unordered_set<size_t>& bits,
               ExecutionReason exec_reason, Context& ctx);

  // TODO: put them into HierarFlow
  bool Minimize(QueueItem& input, size_t start_index, size_t end_index);
  bool DeterministicTreeMutation(QueueItem& input, size_t start_index,
                                 size_t end_index);

  std::shared_ptr<const NautilusSetting> setting;
  std::shared_ptr<executor::AFLExecutorInterface> executor;

  /* Local state */
  Context ctx;
  ChunkStore cks;
  Mutator mutator;

  /* Global shared state */
  Queue queue;
  std::unordered_map<bool, std::vector<uint8_t>> bitmaps;  // is_crash-->bitmap
  uint64_t execution_count;
  uint64_t average_executions_per_sec;
  uint64_t bits_found_by_havoc;
  uint64_t bits_found_by_havoc_rec;
  uint64_t bits_found_by_min;
  uint64_t bits_found_by_min_rec;
  uint64_t bits_found_by_splice;
  uint64_t bits_found_by_det;
  uint64_t bits_found_by_gen;
  uint64_t asan_found_by_havoc;
  uint64_t asan_found_by_havoc_rec;
  uint64_t asan_found_by_min;
  uint64_t asan_found_by_min_rec;
  uint64_t asan_found_by_splice;
  uint64_t asan_found_by_det;
  uint64_t asan_found_by_gen;
  std::string last_found_asan;
  std::string last_found_sig;
  std::string last_timeout;
  std::string state_saved;
  uint64_t total_found_asan;
  uint64_t total_found_sig;
  uint64_t total_found_hang;
  // Added
  std::chrono::system_clock::time_point start_time;
  std::chrono::system_clock::time_point last_time;
  uint32_t cycles_done;

  /* Fuzzer */
  std::unordered_set<std::string> last_tried_inputs;
  std::deque<std::string> last_inputs_ring_buffer;
};

}  // namespace fuzzuf::algorithm::nautilus::fuzzer

#endif
