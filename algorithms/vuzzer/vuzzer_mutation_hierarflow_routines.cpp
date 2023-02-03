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
 * @file VUzzerMutationHierarFlowRoutines.hpp
 * @brief HieraFlow nodes for mutation methods
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/vuzzer/vuzzer_mutation_hierarflow_routines.hpp"

#include "fuzzuf/algorithms/vuzzer/vuzzer_mutator.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::vuzzer::routine::mutation {

Mutate::Mutate(VUzzerState &state) : state(state) {}

/**
 * @brief Choose two seeds from seed_queue randomly, mutate and save them as new
 * seeds in pending_queue.
 */
VUzzerMutCalleeRef Mutate::operator()(void) {
  DEBUG("Mutate seed(%zu)\n", state.seed_queue.size());
  assert(state.seed_queue.size() >=
         2);  // Mutator use at least two seeds from seed_queue

  std::random_device rd;
  std::default_random_engine eng(rd());
  std::uniform_real_distribution<> distr_cut(0.4, 0.8),
      distr_mut(0.1, 1.0);                              // XXX:
  u32 best_len = state.seed_queue[0]->input->GetLen();  // XXX

  /* TODO: filesTrim */
  /* TODO: best=set(fitnames[:config.BESTP]) */
  int limit = state.setting->pop_size - state.setting->next_gen_range;

  for (int i = 0; i < limit; i += 2) {
    std::vector<std::shared_ptr<VUzzerTestcase>> parents;

    /* Choose two seeds from seed_queue. */
    u32 cutp = (int)(distr_cut(eng) * state.seed_queue.size());
    std::sample(state.seed_queue.begin() + cutp, state.seed_queue.end(),
                std::back_inserter(parents), 2,
                std::mt19937{std::random_device{}()});

    /* If we have seeds in taint_queue, choose them randomly. */
    if (state.taint_queue.size()) {
      if ((u32)(rand() % 10) > state.setting->next_gen_from_special_prob) {
        parents[0] = state.taint_queue[rand() % state.taint_queue.size()];
      }
      if ((u32)(rand() % 10) > state.setting->next_gen_from_special_prob) {
        parents[1] = state.taint_queue[rand() % state.taint_queue.size()];
      }
    }

    DEBUG("Chose %s, %s", parents[0]->input->GetPath().c_str(),
          parents[1]->input->GetPath().c_str());

    parents[0]->input->LoadByMmap();
    parents[1]->input->LoadByMmap();

    if (parents[0]->input->GetLen() > best_len ||
        parents[1]->input->GetLen() > best_len) {
      DEBUG("No crossover");
      auto mutator1 = VUzzerMutator(*parents[0]->input, state);
      auto mutator2 = VUzzerMutator(*parents[1]->input, state);
      mutator1.MutateRandom();
      mutator1.TaintBasedChange();
      mutator2.MutateRandom();
      mutator2.TaintBasedChange();

      /* Save new seeds in pending_queue */
      std::string fn = fuzzuf::utils::StrPrintf("%s/queue/id:%06u",
                                                state.setting->out_dir.c_str(),
                                                state.queued_paths);
      state.AddToQueue(state.pending_queue, fn, mutator1.GetBuf(),
                       mutator1.GetLen());

      fn = fuzzuf::utils::StrPrintf("%s/queue/id:%06u",
                                    state.setting->out_dir.c_str(),
                                    state.queued_paths);
      state.AddToQueue(state.pending_queue, fn, mutator2.GetBuf(),
                       mutator2.GetLen());

    } else {
      DEBUG("Crossover");
      auto crossover = VUzzerMutator(*parents[0]->input, state);
      /* FIXME: Do not use ExecInputSet(input_set) */
      auto seeds = crossover.CrossOver(*parents[1]->input);

      auto mutator1 = VUzzerMutator(*(seeds.first), state);
      auto mutator2 = VUzzerMutator(*(seeds.second), state);

      if (distr_mut(eng) > (1.0 - state.setting->mutate_after_crossover_prob)) {
        mutator1.MutateRandom();
        mutator1.TaintBasedChange();
      } else {
        mutator1.TaintBasedChange();
      }

      /* Save a new seed in pending_queue */
      std::string fn = fuzzuf::utils::StrPrintf("%s/queue/id:%06u,crossover",
                                                state.setting->out_dir.c_str(),
                                                state.queued_paths);
      state.AddToQueue(state.pending_queue, fn, mutator1.GetBuf(),
                       mutator1.GetLen());

      if (distr_mut(eng) > (1.0 - state.setting->mutate_after_crossover_prob)) {
        mutator2.MutateRandom();
        mutator2.TaintBasedChange();
      } else {
        mutator2.TaintBasedChange();
      }

      /* Save a new seed in pending_queue */
      fn = fuzzuf::utils::StrPrintf("%s/queue/id:%06u,crossover",
                                    state.setting->out_dir.c_str(),
                                    state.queued_paths);
      state.AddToQueue(state.pending_queue, fn, mutator2.GetBuf(),
                       mutator2.GetLen());
    }

    parents[0]->input->Unload();
    parents[1]->input->Unload();
  }
  CallSuccessors();
  return GoToDefaultNext();
}

}  // namespace fuzzuf::algorithm::vuzzer::routine::mutation
