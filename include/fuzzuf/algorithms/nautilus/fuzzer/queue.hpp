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
 * @file queue.hpp
 * @brief Corpus queue of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_QUEUE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_FUZZER_QUEUE_HPP

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/recursion_info.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

using namespace fuzzuf::algorithm::nautilus::grammartec;

using InitState = size_t;
using DetState = std::pair<size_t, size_t>;
using RandomState = std::monostate;

struct QueueItem {
  QueueItem() = delete;
  QueueItem(size_t id, Tree&& tree, std::unordered_set<size_t>&& fresh_bits,
            const std::vector<uint8_t>&& all_bits,
            feedback::PUTExitReasonType exit_reason, uint64_t execution_time)
      : id(id),
        tree(std::move(tree)),
        fresh_bits(std::move(fresh_bits)),
        all_bits(std::move(all_bits)),
        exit_reason(exit_reason),
        state(InitState(0)),
        recursions(std::nullopt),
        execution_time(execution_time) {}

  size_t id;
  Tree tree;
  std::unordered_set<size_t> fresh_bits;
  std::vector<uint8_t> all_bits;
  feedback::PUTExitReasonType exit_reason;
  std::variant<InitState, DetState, RandomState> state;
  std::optional<std::vector<RecursionInfo>> recursions;
  uint64_t execution_time;
};

class Queue {
 public:
  Queue(std::string work_dir) : _current_id(0), _work_dir(work_dir) {}
  const std::vector<std::unique_ptr<QueueItem>>& inputs() const {
    return _inputs;
  }
  size_t size() const { return _inputs.size(); }

  void Add(Tree&& tree, const std::vector<uint8_t>&& all_bits,
           feedback::PUTExitReasonType exit_reason, Context& ctx,
           uint64_t execution_time);
  std::unique_ptr<QueueItem> Pop();
  bool IsEmpty() const;
  void Finished(std::unique_ptr<QueueItem> item);
  void NewRound();

 private:
  std::vector<std::unique_ptr<QueueItem>> _inputs;
  std::vector<std::unique_ptr<QueueItem>> _processed;
  std::unordered_map<size_t, std::vector<size_t>> _bit_to_inputs;
  size_t _current_id;
  std::string _work_dir;
};

}  // namespace fuzzuf::algorithm::nautilus::fuzzer

#endif
