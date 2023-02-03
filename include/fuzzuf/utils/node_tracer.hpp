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
 * @file node_tracer.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_NODE_TRACER_HPP
#define FUZZUF_INCLUDE_UTILS_NODE_TRACER_HPP

#include <config.h>

#include <chrono>
#include <functional>
#include <string>
#include <type_traits>

#include "config.h"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/to_hex.hpp"
#include "fuzzuf/utils/to_string.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
namespace fuzzuf::utils {

/**
 * @class NodeTracerTag
 * @brief
 * If the fuzzer argument type T has member type T::tag and T::tag is
 * NodeTracerTag, the argument is considered as node tracer to send events
 */
struct NodeTracerTag {};

template <typename T, typename Enable = void>
struct IsNodeTracer : public std::false_type {};
template <typename T>
struct IsNodeTracer<
    T, std::enable_if_t<std::is_same_v<
           typename utils::type_traits::RemoveCvrT<T>::tag, NodeTracerTag>>>
    : public std::true_type {};
template <typename T>
constexpr bool is_node_tracer_v = IsNodeTracer<T>::value;

enum class Checkpoint {
  enter,      // entered to the node
  leave,      // leaved from the node
  abort,      // aborted from the node
  break_,     // loop node finished the loop
  continue_,  // loop node is going to run at least one more cycle
  finalize,   // no longer used
  mark        // entered to the Marker node
};

/**
 * @class DumpTracer
 * @brief Simply serialize incoming events, then output it using sink
 * It is handy way to generate debug output
 * This node ignore all additional arguments
 */
class DumpTracer {
 public:
  using tag = NodeTracerTag;
  DumpTracer(std::function<void(std::string &&)> &&s) : sink(std::move(s)) {}
  /**
   * The function is called when an event with non-string value and without code
   * location infomation is sent Serialize the value then output to sink
   */
  template <typename T>
  auto operator()(const T &v) const -> std::enable_if_t<
      !std::is_same_v<utils::type_traits::RemoveCvrT<T>, char *> &&
      !std::is_same_v<utils::type_traits::RemoveCvrT<T>, std::string>> {
    std::string m;
    utils::toStringADL(m, v, 0, "  ");
    sink(std::move(m));
  }
  /**
   * The function is called when an event with std::string value and without
   * code location infomation is sent Just output value to sink
   */
  void operator()(const std::string &v) const;
  /**
   * The function is called when an event with const char* value and without
   * code location infomation is sent Just output value to sink
   */
  void operator()(const char *v) const;
  /**
   * The function is called when an event with code location infomation is sent
   * Serialize the infomation then output to sink
   */
  template <typename Node, typename... Args>
  void operator()(
#ifdef ENABLE_NODE_TRACER_LOCATION_DUMPER
      const char *file, int line,
#else
      const char *, int,
#endif
      const char *node_name,
#ifdef ENABLE_NODE_TRACER_ADDRESS_DUMPER
      const Node &node,
#else
      const Node &,
#endif
      Checkpoint checkpoint, const Args &...) {
#ifdef ENABLE_NODE_TRACER_LOCATION_DUMPER
    std::string m(file);
    m += '(';
    utils::toString(m, line);
    m += ") : ";
#else
    std::string m;
#endif
#ifndef ENABLE_NODE_TRACER_TRANSPARENT_DUMPER
    if (node_name == std::string("Nop")) return;
#endif
    if (checkpoint == Checkpoint::enter)
      m += "enter ";
    else if (checkpoint == Checkpoint::leave)
      m += "leave ";
    else if (checkpoint == Checkpoint::abort)
      m += "abort ";
    else if (checkpoint == Checkpoint::break_)
      m += "break ";
    else if (checkpoint == Checkpoint::continue_)
      m += "continue ";
    else if (checkpoint == Checkpoint::finalize)
      m += "finalize ";
    else if (checkpoint == Checkpoint::mark)
      m += "mark ";
    else
      m += "unknown event on ";
    m += node_name;
#ifdef ENABLE_NODE_TRACER_ADDRESS_DUMPER
    m += "(0x";
    toHex(m, reinterpret_cast<std::uintptr_t>(&node));
    m += ")\n";
#else
    m += "\n";
#endif
    sink(std::move(m));
  }

 private:
  std::function<void(std::string &&)> sink;
};

/**
 * @class MarkingTracer
 * @brief Record only detail of markers
 * This tracer is intended to check if control node is controlling flow properly
 * in unit tests. This node uses first additional argument as the infomation to
 * identify markers
 */
class MarkingTracer {
 public:
  using tag = NodeTracerTag;
  using log_type = std::vector<std::pair<const char *, std::string>>;
  /**
   * The function is called when an event with non-string value and without code
   * location infomation is sent MarkingTracer ignores all events without
   * Checkpoint::mark
   */
  template <typename T>
  auto operator()(const T &) const -> std::enable_if_t<
      !std::is_same_v<utils::type_traits::RemoveCvrT<T>, char *> &&
      !std::is_same_v<utils::type_traits::RemoveCvrT<T>, std::string>> {}
  /**
   * The function is called when an event with std::string value and without
   * code location infomation is sent MarkingTracer ignores all events without
   * Checkpoint::mark
   */
  void operator()(const std::string &) const {}
  /**
   * The function is called when an event with const char* value and without
   * code location infomation is sent MarkingTracer ignores all events without
   * Checkpoint::mark
   */
  void operator()(const char *) const {}
  /**
   * The function is called when an event with code location infomation is sent
   * record node name and identifier to the log if checkpoint is
   * Checkpoint::mark
   */
  template <typename Node, typename Head, typename... Tail>
  void operator()(const char *, int, const char *node_name, const Node &,
                  Checkpoint checkpoint, const Head &head, const Tail &...) {
    if (checkpoint == Checkpoint::mark) {
      std::string m;
      utils::toStringADL(m, head);
      log.emplace_back(node_name, std::move(m));
    }
  }
  /**
   * The function is called when an event with code location infomation is sent
   * record node name to the log if checkpoint is Checkpoint::mark
   */
  template <typename Node>
  void operator()(const char *, int, const char *node_name, const Node &,
                  Checkpoint checkpoint) {
    if (checkpoint == Checkpoint::mark) {
      log.emplace_back(node_name, std::string());
    }
  }
  /**
   * retrive recorded log
   */
  const log_type &get_log() const { return log; }

 private:
  log_type log;
};

/**
 * @class ElapsedTimeTracer
 * @brief Record time duration from Checkpoint::enter to Checkpoint::leave for
 * each node names The tracer is intended to detect heavy node The tracer
 * records two kind of durations Inclusive duration is elapsed time between
 * enter and leave including whole child node execution time Exclusive duration
 * is elapsed time between enter and leave excluding child node execution time
 */
class ElapsedTimeTracer {
  struct ElapsedTimeT {
    ElapsedTimeT(
        const std::string &name_,
        const std::chrono::high_resolution_clock::time_point &inclusive_,
        const std::chrono::high_resolution_clock::time_point &exclusive_)
        : name(name_), inclusive(inclusive_), exclusive(exclusive_) {}
    std::string name;
    std::chrono::high_resolution_clock::time_point inclusive;
    std::chrono::high_resolution_clock::time_point exclusive;
  };
  struct SumT {
    std::int64_t inclusive = 0ull;
    std::int64_t exclusive = 0ull;
    std::uint64_t count = 0ull;
  };

 public:
  using tag = NodeTracerTag;
  void dump(const std::function<void(std::string &&)> &s) {
    {
      std::vector<std::pair<std::string, SumT>> sorted(summary.begin(),
                                                       summary.end());
      std::sort(sorted.begin(), sorted.end(), [](const auto &l, const auto &r) {
        return l.second.inclusive >= r.second.inclusive;
      });
      std::string m = "Inclusive: \n";
      for (auto &[name, s] : sorted) {
        m += "  ";
        m += name;
        m += " : ";
        m += std::to_string(s.inclusive);
        m += "us / ";
        m += std::to_string(s.count);
        m += "calls = ";
        m += std::to_string(s.inclusive / s.count);
        m += "us / 1 call\n";
      }
      s(std::move(m));
    }
    {
      std::vector<std::pair<std::string, SumT>> sorted(summary.begin(),
                                                       summary.end());
      std::sort(sorted.begin(), sorted.end(), [](const auto &l, const auto &r) {
        return l.second.exclusive >= r.second.exclusive;
      });
      std::string m = "Exclusive: \n";
      for (auto &[name, s] : sorted) {
        m += "  ";
        m += name;
        m += " : ";
        m += std::to_string(s.exclusive);
        m += "us / ";
        m += std::to_string(s.count);
        m += "calls = ";
        m += std::to_string(s.exclusive / s.count);
        m += "us / 1 call\n";
      }
      s(std::move(m));
    }
  }
  /**
   * The function is called when an event without code location infomation is
   * sent The tracer ignores events without location infomation
   */
  template <typename T>
  auto operator()(const T &v) const -> void {}
  /**
   * The function is called when an event with code location infomation is sent
   * If the checkpoint is enter, record begin date
   * If the checkpoint is leave, subtract begin date from current date, then
   * append the duration to total duration
   */
  template <typename Node, typename... Args>
  void operator()(const char *, int, const char *node_name, const Node &,
                  Checkpoint checkpoint, const Args &...) {
    auto now = std::chrono::high_resolution_clock::now();
    if (checkpoint == Checkpoint::enter) {
      if (!call_stack.empty()) {
        summary[call_stack.back().name].exclusive +=
            std::chrono::duration_cast<std::chrono::microseconds>(
                now - call_stack.back().exclusive)
                .count();
      }
      call_stack.emplace_back(node_name, now, now);
    } else if (checkpoint == Checkpoint::leave) {
      if (!call_stack.empty()) {
        if (call_stack.back().name != node_name) {
          throw exceptions::unexpected_leave_event();
        }
        auto existing = summary.find(call_stack.back().name);
        if (existing != summary.end()) {
          existing->second.exclusive +=
              std::chrono::duration_cast<std::chrono::microseconds>(
                  now - call_stack.back().exclusive)
                  .count();
          existing->second.inclusive +=
              std::chrono::duration_cast<std::chrono::microseconds>(
                  now - call_stack.back().inclusive)
                  .count();
          existing->second.count += 1u;
        } else {
          summary.insert(std::make_pair(
              call_stack.back().name,
              SumT{std::chrono::duration_cast<std::chrono::microseconds>(
                       now - call_stack.back().exclusive)
                       .count(),
                   std::chrono::duration_cast<std::chrono::microseconds>(
                       now - call_stack.back().inclusive)
                       .count(),
                   1u}));
        }
        call_stack.pop_back();
      }
      if (!call_stack.empty()) {
        call_stack.back().exclusive = now;
      }
    }
  }

 private:
  std::vector<ElapsedTimeT> call_stack;
  std::unordered_map<std::string, SumT> summary;
};

}  // namespace fuzzuf::utils

#endif
