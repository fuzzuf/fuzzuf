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
 * @file standard_end.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END_HPP

#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
/**
 * Macro to generate standard child nodes invocation.
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(name)   \
  if (this->CallSuccessors(std::forward<Args>(args)...)) {         \
    base_type::SetResponseValue(true);                             \
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(#name, abort) \
    return base_type::GoToParent();                                \
  }                                                                \
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(#name, leave)   \
  return base_type::GoToDefaultNext();

#endif
