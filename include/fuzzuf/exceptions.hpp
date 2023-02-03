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
#ifndef __EXCEPTIONS_HPP__
#define __EXCEPTIONS_HPP__
#include <stdexcept>
namespace fuzzuf::exceptions {

#define FUZZUF_BASE_EXCEPTION(base, name)                         \
  struct name : public base {                                     \
    name() : base(#name), file("unknown"), line(0) {}             \
    name(const std::string &what_arg, const char *file, int line) \
        : base(what_arg), file(file), line(line) {}               \
    name(const char *what_arg, const char *file, int line)        \
        : base(what_arg), file(file), line(line) {}               \
    const char *file;                                             \
    int line;                                                     \
  };
#define FUZZUF_INHERIT_EXCEPTION(base, name) \
  struct name : public base {                \
    using base ::base;                       \
    name() : base(#name, "unknown", 0) {}    \
  };
FUZZUF_BASE_EXCEPTION(std::logic_error, fuzzuf_logic_error)
FUZZUF_BASE_EXCEPTION(std::runtime_error, fuzzuf_runtime_error)
FUZZUF_BASE_EXCEPTION(std::invalid_argument, fuzzuf_invalid_argument)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_logic_error, used_after_free)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_logic_error, wrong_hierarflow_usage)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_logic_error, not_implemented)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_logic_error, unreachable)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_runtime_error, execution_failure)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_runtime_error, unable_to_create_file)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_runtime_error, invalid_file)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_runtime_error, cli_error)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_runtime_error, logger_error)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_logic_error, unexpected_leave_event)
FUZZUF_INHERIT_EXCEPTION(fuzzuf_invalid_argument, invalid_argument)
}  // namespace fuzzuf::exceptions
#endif
