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
 * @file dump.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_DUMP_HPP
#define FUZZUF_INCLUDE_ALGORITHM_LIBFUZZER_HIERARFLOW_DUMP_HPP
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_end.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/standard_typedef.hpp"
#include "fuzzuf/algorithms/libfuzzer/hierarflow/trace.hpp"
#include "fuzzuf/algorithms/libfuzzer/mutation.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/utils/call_with_nth.hpp"
#include "fuzzuf/utils/to_string.hpp"

namespace fuzzuf::algorithm::libfuzzer {

/**
 * @class StaticDump
 * @brief Serialize a value specified by the Path and call sink to output it.
 * This node is intended to make debugging easier.
 * The node takes 1 path for the value.
 * @tparam F Function type to define what arguments passes through this node.
 * @tparam Path Struct path to define which value to to use.
 */
template <typename F, typename Path>
class StaticDump {};
template <typename R, typename... Args, typename Path>
class StaticDump<R(Args...), Path>
    : public hierarflow::HierarFlowRoutine<R(Args...), R(Args...)> {
 public:
  FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_TYPEDEFS
  /**
   * Constructor
   * @tparam Sink Type of sink
   * @param prefix_ This message is added to the head of serialized message
   * @param indent_count_
   * Initial indentation depth. This value is used if the value is serialized
   * into multiple lines.
   * @param indent_
   * Indentation string. This value is inserted for each indentation at the head
   * of line. This value is used if the value is serialized into multiple lines.
   * @param sink_ Callback function with one string as an argument. This
   * function is called to output serialized message.
   */
  template <typename Sink>
  StaticDump(const std::string &prefix_, std::size_t indent_count_,
             const std::string &indent_, Sink &&sink_)
      : prefix(prefix_),
        indent_count(indent_count_),
        indent(indent_),
        sink(std::forward<Sink>(sink_)) {}
  /**
   * This callable is called on HierarFlow execution
   * @param args Arguments
   * @return direction of next node
   */
  callee_ref_t operator()(Args... args) {
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_CHECKPOINT("StaticDump", enter)
    std::string dest = prefix;
    if (!dest.empty() && dest.back() != '\n') dest += '\n';
    Path()([&](auto &&v) { utils::toStringADL(dest, v, indent_count, indent); },
           std::forward<Args>(args)...);
    sink(std::move(dest));
    FUZZUF_ALGORITHM_LIBFUZZER_HIERARFLOW_STANDARD_END(StaticDump)
  }

 private:
  std::string prefix;
  std::size_t indent_count;
  std::string indent;
  std::function<void(std::string &&)> sink;
};

}  // namespace fuzzuf::algorithm::libfuzzer
#endif
