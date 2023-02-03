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
 * @file trace.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_TRACE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_TRACE_HPP

#include "config.h"
#include "fuzzuf/utils/call_with_detected.hpp"
#include "fuzzuf/utils/node_tracer.hpp"

#if defined(__clang__) || !defined(ENABLE_NODE_TRACER)
/*
 * All event generators are skipped until -DENABLE_NODE_TRACER is set.
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_TRACE(event)
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(node_name, checkpoint)
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_MARK(node_name, checkpoint)
#else
/*
 * Macro to generate versatile event received by NodeTracer
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_TRACE(event)      \
  fuzzuf::utils::callWithDetected<fuzzuf::utils::IsNodeTracer>( \
      [&](auto &&tracer) { tracer(event); }, std::forward<Args>(args)...);
/**
 * Macro to generate event that indicates enter and leave of nodes, those are
 * received by NodeTracer
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT(node_name,  \
                                                         checkpoint) \
  fuzzuf::utils::callWithDetected<fuzzuf::utils::IsNodeTracer>(      \
      [&](auto &&tracer) {                                           \
        tracer(__FILE__, __LINE__, node_name, *this,                 \
               fuzzuf::utils::Checkpoint::checkpoint, args...);      \
      },                                                             \
      std::forward<Args>(args)...);
/**
 * Macro to generate "mark" event received by NodeTracer
 */
#define FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_MARK(node_name, info) \
  fuzzuf::utils::callWithDetected<fuzzuf::utils::IsNodeTracer>(     \
      [&](auto &&tracer) {                                          \
        tracer(__FILE__, __LINE__, node_name, *this,                \
               fuzzuf::utils::Checkpoint::mark, info);              \
      },                                                            \
      std::forward<Args>(args)...);
#endif

#endif
