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
 * @file chunkstore.hpp
 * @brief Disk storage to save (sub)trees
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_CHUNKSTORE_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_CHUNKSTORE_HPP

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/newtypes.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

using Chunk = std::pair<size_t, NodeID>;
using AlternativePair = std::pair<std::unique_ptr<Tree>, NodeID>;

class ChunkStore {
 public:
  ChunkStore(const std::string& work_dir)
      : _work_dir(work_dir), _number_of_chunks(0) {}
  std::unordered_map<NTermID, std::vector<Chunk>>& nts_to_chunks() {
    return _nts_to_chunks;
  }
  std::vector<Tree>& trees() { return _trees; }
  std::unordered_set<std::string>& seen_outputs() { return _seen_outputs; }

  void AddTree(Tree& tree, Context& ctx);
  std::optional<AlternativePair> GetAlternativeTo(const RuleID& r,
                                                  Context& ctx) const;

 private:
  std::unordered_map<NTermID, std::vector<Chunk>> _nts_to_chunks;
  std::unordered_set<std::string> _seen_outputs;
  std::vector<Tree> _trees;
  std::string _work_dir;
  size_t _number_of_chunks;
};

}  // namespace fuzzuf::algorithm::nautilus::grammartec

#endif
