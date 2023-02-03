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
 * @file chunkstore.cpp
 * @brief Disk storage to save (sub)trees
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 *
 * @details This file implements the storage to store subtrees.
 *          These trees are used by the mutation engine.
 */
#include "fuzzuf/algorithms/nautilus/grammartec/chunkstore.hpp"

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/random.hpp"

namespace fuzzuf::algorithm::nautilus::grammartec {

/**
 * @fn
 * Save a tree to the storage if it's never seen before.
 * @brief Add a tree to this storage
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
      std::string filepath = fuzzuf::utils::StrPrintf(
          "%s/chunks/chunk_%09ld", _work_dir.c_str(), _number_of_chunks++);
      int fd = fuzzuf::utils::OpenFile(filepath, O_WRONLY | O_CREAT | O_TRUNC,
                                       S_IWUSR | S_IRUSR);  // 0600
      if (fd == -1) {
        throw exceptions::unable_to_create_file(
            fuzzuf::utils::StrPrintf("Cannot save tree: %s", filepath.c_str()),
            __FILE__, __LINE__);
      }
      fuzzuf::utils::WriteFile(fd, buffer.data(), buffer.size());
      fuzzuf::utils::CloseFile(fd);

      contains_new_chunk = true;
    }
  }

  if (contains_new_chunk) {
    _trees.push_back(tree);
  }
}

/**
 * @fn
 * Randomly choose a pair of a tree and a node that derives from a rule.
 * @brief Choose a subtree that can alter a specific rule.
 * @param (r) Rule ID
 * @param (ctx) Context
 * @return A pair of tree and node if any, otherwise nothing
 *
 * @details This method tries to find a subtree that share the same
 *          nonterminal as that if the given rule.
 *          This function is used by the random recursive mutation.
 */
std::optional<AlternativePair> ChunkStore::GetAlternativeTo(
    const RuleID& r, Context& ctx) const {
  NTermID nt = ctx.GetNT(RuleIDOrCustom(r));

  if (_nts_to_chunks.find(nt) == _nts_to_chunks.end()) {
    // TODO: is this correct?
    return std::nullopt;
  }

  const std::vector<Chunk>& chunks = _nts_to_chunks.at(nt);

  std::vector<Chunk> relevant;
  for (const Chunk& chunk : chunks) {
    auto& [tid, nid] = chunk;
    if (_trees.at(tid).GetRuleID(nid) != r) {
      relevant.emplace_back(tid, nid);
    }
  }

  if (relevant.size() == 0) {
    return std::nullopt;
  }

  Chunk selected = utils::random::Choose(relevant);
  return std::make_pair(
      std::move(std::make_unique<Tree>(_trees.at(selected.first))),
      selected.second);
}

}  // namespace fuzzuf::algorithm::nautilus::grammartec
