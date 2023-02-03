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
 * @file die_hierarflow_routines.hpp
 * @brief Hierarflow routines for DIE
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <memory>

#include "fuzzuf/algorithms/die/die_mutator.hpp"
#include "fuzzuf/algorithms/die/die_state.hpp"
#include "fuzzuf/algorithms/die/die_testcase.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"

namespace fuzzuf::algorithm::die::routine::mutation {

/* Declaration for DIEMutate */

using DIEMutInputType = bool(std::shared_ptr<DIETestcase>);
using DIEMutCalleeRef =
    utils::NullableRef<hierarflow::HierarFlowCallee<DIEMutInputType>>;
using DIEMutOutputType = bool(const u8 *, u32, const u8 *, u32);

struct DIEMutate
    : public hierarflow::HierarFlowRoutine<DIEMutInputType, DIEMutOutputType> {
 public:
  DIEMutCalleeRef operator()(std::shared_ptr<DIETestcase>);
  DIEMutate(DIEState &state) : state(state) {}

 private:
  DIEState &state;
};

}  // namespace fuzzuf::algorithm::die::routine::mutation

namespace fuzzuf::algorithm::die::routine::other {

/* Declaration for DIEExecute */

using DIEExecInputType = bool(const u8 *, u32,  // js file
                              const u8 *,
                              u32);  // type file (extended from AFL)
using DIEExecCalleeRef =
    utils::NullableRef<hierarflow::HierarFlowCallee<DIEExecInputType>>;
using DIEExecOutputType = bool(const u8 *, u32,  // js file
                               const u8 *,
                               u32,  // type file (extended from AFL)
                               feedback::InplaceMemoryFeedback &,
                               feedback::ExitStatusFeedback &);

struct DIEExecute : public hierarflow::HierarFlowRoutine<DIEExecInputType,
                                                         DIEExecOutputType> {
 public:
  DIEExecCalleeRef operator()(const u8 *, u32, const u8 *, u32);
  DIEExecute(DIEState &state) : state(state) {}

 private:
  DIEState &state;
};

}  // namespace fuzzuf::algorithm::die::routine::other

namespace fuzzuf::algorithm::die::routine::update {

/* Declaration for DIEUpdate */

using DIEUpdateInputType = bool(const u8 *, u32, const u8 *, u32,
                                feedback::InplaceMemoryFeedback &,
                                feedback::ExitStatusFeedback &);
using DIEUpdateCalleeRef =
    utils::NullableRef<hierarflow::HierarFlowCallee<DIEUpdateInputType>>;
using DIEUpdateOutputType = void(void);

struct DIEUpdate : public hierarflow::HierarFlowRoutine<DIEUpdateInputType,
                                                        DIEUpdateOutputType> {
 public:
  DIEUpdateCalleeRef operator()(const u8 *, u32, const u8 *, u32,
                                feedback::InplaceMemoryFeedback &,
                                feedback::ExitStatusFeedback &);
  DIEUpdate(DIEState &state) : state(state) {}

 private:
  DIEState &state;
};

}  // namespace fuzzuf::algorithm::die::routine::update
