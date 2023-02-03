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
 * @file to_string.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/to_string.hpp"

#include <boost/spirit/include/karma.hpp>
#include <cstddef>

namespace fuzzuf::utils {

auto toString(std::string &dest, bool value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::bool_, value);
}

auto toString(std::string &dest, unsigned char value) -> bool {
  return toString(dest, static_cast<unsigned short>(value));
}

auto toString(std::string &dest, signed char value) -> bool {
  return toString(dest, static_cast<signed short>(value));
}

auto toString(std::string &dest, unsigned short value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::ushort_, value);
}

auto toString(std::string &dest, signed short value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::short_, value);
}

auto toString(std::string &dest, unsigned int value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::uint_, value);
}

auto toString(std::string &dest, signed int value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::int_, value);
}

auto toString(std::string &dest, unsigned long value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::ulong_, value);
}

auto toString(std::string &dest, signed long value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::long_, value);
}

auto toString(std::string &dest, unsigned long long value) -> bool {
  return boost::spirit::karma::generate(
      std::back_inserter(dest), boost::spirit::karma::ulong_long, value);
}

auto toString(std::string &dest, signed long long value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::long_long, value);
}

auto toString(std::string &dest, float value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::float_, value);
}

auto toString(std::string &dest, double value) -> bool {
  return boost::spirit::karma::generate(std::back_inserter(dest),
                                        boost::spirit::karma::double_, value);
}

auto toString(std::string &dest, long double value) -> bool {
  return boost::spirit::karma::generate(
      std::back_inserter(dest), boost::spirit::karma::long_double, value);
}

#define FUZZUF_UTILS_CHRONO_TO_STRING(name)                                \
  auto toString(std::string &dest, const std::chrono::name &value)->bool { \
    if (!toString(dest, value.count())) return false;                      \
    dest += #name;                                                         \
    return true;                                                           \
  }

FUZZUF_UTILS_CHRONO_TO_STRING(nanoseconds)
FUZZUF_UTILS_CHRONO_TO_STRING(microseconds)
FUZZUF_UTILS_CHRONO_TO_STRING(milliseconds)
FUZZUF_UTILS_CHRONO_TO_STRING(seconds)
FUZZUF_UTILS_CHRONO_TO_STRING(minutes)
FUZZUF_UTILS_CHRONO_TO_STRING(hours)

#if __cplusplus >= 202002L
FUZZUF_UTILS_CHRONO_TO_STRING(days)
FUZZUF_UTILS_CHRONO_TO_STRING(weeks)
FUZZUF_UTILS_CHRONO_TO_STRING(months)
FUZZUF_UTILS_CHRONO_TO_STRING(years)
#endif

auto toString(std::string &dest, const std::string &value) -> bool {
  dest += '"';
  dest += value;
  dest += '"';
  return true;
}

void make_indent(std::string &dest, std::size_t indent_count,
                 const std::string &indent) {
  for (std::size_t i = 0U; i != indent_count; ++i) {
    dest += indent;
  }
}

}  // namespace fuzzuf::utils
