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
 * @file executor.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_CC_INCLUDE_UTILS_EXECUTOR_HPP
#define FUZZUF_CC_INCLUDE_UTILS_EXECUTOR_HPP
#include <sys/epoll.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <tuple>
#include <vector>

#include "forkserver/config.h"
#include "fuzzuf/utils/setter.hpp"
#include "fuzzuf/utils/instrumentation_info.hpp"
#include "fuzzuf/utils/pipe.hpp"

namespace fuzzuf::utils {

struct ExecutorParameters {
  FUZZUF_SETTER(intrusive_input_value)
  FUZZUF_SETTER(args)
  FUZZUF_SETTER(env)
  FUZZUF_SETTER(timeout)
  bool intrusive_input_value = false;
  std::vector<std::string> args;
  std::vector<std::string> env;
  std::time_t timeout;
  ExecutorParameters&& move() { return std::move(*this); }
};

class Executor {
 public:
  /**
   * Constructor
   * @param args_ arguments of PUT
   * @param env_ environment variables for forkserver process
   */
  Executor(ExecutorParameters&&);
  Executor(const Executor&) = delete;
  Executor(Executor&&) = delete;
  Executor& operator=(const Executor&) = delete;
  Executor& operator=(Executor&&) = delete;
  ~Executor();
  /**
   * Run PUT once
   * @param standard_input the value is passed to the PUT by standard input
   * @return tuple of execution result, standard output from the PUT and
   * standard error from the PUT
   */
  std::tuple<ExecutePUTAPIResponse, std::vector<std::byte>,
             std::vector<std::byte> >
  operator()(const std::vector<std::byte>& standard_input);
  template <typename Range>
  auto operator()(const Range& r)
#if __cplusplus >= 202002L
      -> std::tuple<ExecutePUTAPIResponse, std::vector<std::byte>,
                    std::vector<std::byte> >
  requires requires {
    !std::is_same_v<std::remove_cv_t<std::remove_reference_t<Range> >,
                    std::vector<std::byte> >;
  }
#else
      -> std::enable_if_t<
          !std::is_same_v<std::remove_cv_t<std::remove_reference_t<Range> >,
                          std::vector<std::byte> >,
          std::tuple<ExecutePUTAPIResponse, std::vector<std::byte>,
                     std::vector<std::byte> > >
#endif
  { return operator()(std::vector<std::byte>(r.begin(), r.end())); }
  std::tuple<ExecutePUTAPIResponse, std::vector<std::byte>,
             std::vector<std::byte> >
  operator()() {
    return operator()(std::vector<std::byte>{});
  }

 private:
  void Execute();
  std::vector<std::string> args;
  std::vector<char*> argv;
  std::vector<std::string> env;
  std::vector<char*> envp;
  bool intrusive_input_value;
  std::uint64_t executor_id = 1u;
  pid_t fork_server_pid = 0;
  Pipe to_fork_server;
  Pipe from_fork_server;
  Pipe target_stdin;
  Pipe target_stdout;
  Pipe target_stderr;
  int epoll_fd = -1;
  epoll_event stdin_event;
  epoll_event stdout_event;
  epoll_event stderr_event;
  epoll_event from_fork_server_event;
  InstrumentationInfo instrumentation_info;
};

}

#endif

