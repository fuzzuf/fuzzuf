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
 * @file other_hierarflow_routines.cpp
 * @brief Definition of unclassified HierarFlow routines of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/other_hierarflow_routines.hpp"


namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other {

/**
 * @fn
 * @brief HierarFlow routine for FuzzLoop (fuzz_loop)
 */
NullableRef<HierarFlowCallee<void(void)>> FuzzLoop::operator()(void) {
  CallSuccessors();
  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for SelectInput (select_input)
 */
RSelectInput SelectInput::operator()(void) {
  /** イメージ
      inp = state.queue.pop();
      CallSuccessir(inp);
      return GoToDefaultNext();
   */
  return GoToDefaultNext();
}

/**
 * @fn
 * @brief HierarFlow routine for ProcessInput (process_input_or)
 */
RProcessInput ProcessInput::operator()(QueueItem& inp) {
  inp = inp;
  /** イメージ
      if (input) return CallSuccessor(input.state);
      else return GoToDefaultNext();
   */
  return GoToDefaultNext();
}

} // namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other
