/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file chunkstore.cpp
 * @brief Disk storage to store tree
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"


namespace fuzzuf::algorithms::nautilus::grammartec {

/**
 * @fn
 * @brief Save tree to storage if it's never seen
 * @param (tree) Tree to save
 * @param (ctx) Context
 */
void ChunkStore::AddTree(Tree& tree, Context& ctx) {
  std::string buffer;
  size_t id = _trees.size();
  bool contains_new_chunk = false;

  for (size_t i = 0; i < tree.Size(); i++) {
    buffer.clear();
    if (tree.sizes()[i] > 30) {
      continue;
    }

    NodeID n(i);
    tree.Unparse(n, ctx, buffer);

    if (_seen_outputs.find(buffer) == _seen_outputs.end()) {
      /* This tree has never been seen before */
      _seen_outputs.insert(buffer);
      const NTermID& nt = tree.GetRule(n, ctx).Nonterm();

      if (_nts_to_chunks.find(nt) == _nts_to_chunks.end()) {
        _nts_to_chunks[nt] = {Chunk(id, n)};
      } else {
        _nts_to_chunks[nt].emplace_back(id, n);
      }

      /* Save tree to file */
      int fd = Util::OpenFile(
        Util::StrPrintf("%s/outputs/chunks/chunk_%09ld",
                        _work_dir.c_str(), _number_of_chunks++),
        O_WRONLY | O_CREAT | O_TRUNC,
        S_IWUSR | S_IRUSR // 0600
      );
      Util::WriteFile(fd, buffer.data(), buffer.size());
      Util::CloseFile(fd);

      contains_new_chunk = true;
    }
  }

  if (contains_new_chunk) {
    _trees.push_back(tree);
  }
}

/**
 * @fn
 * @brief Randomly choose a pair of tree and node by rule
 * @param (r) Rule ID
 * @param (ctx) Context
 * @return A pair of tree and node if any, otherwise nothing
 */
std::optional<std::pair<Tree, NodeID>> ChunkStore::GetAlternativeTo(
  const RuleID& r, Context& ctx
) const {
  const std::vector<Chunk>& chunks = _nts_to_chunks.at(
    ctx.GetNT(RuleIDOrCustom(r))
  );

  std::vector<Chunk> relevant;
  for (const Chunk& chunk: chunks) {
    auto& [tid, nid] = chunk;
    if (_trees.at(tid).GetRuleID(nid) != r) {
      relevant.emplace_back(tid, nid);
    }
  }

  if (relevant.size() == 0) {
    return std::nullopt;
  }

  Chunk selected = utils::random::Choose(relevant);
  return std::pair<Tree, NodeID>(_trees.at(selected.first), selected.second);
}

} // namespace fuzzuf::algorithms::nautilus::grammartec
