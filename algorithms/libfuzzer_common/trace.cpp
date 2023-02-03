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
 * @file trace.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/utils/node_tracer.hpp"

namespace fuzzuf::utils {
void DumpTracer::operator()(const std::string &v) const {
  sink(std::string(v) + "\n");
}
void DumpTracer::operator()(const char *v) const {
  std::string m(v != nullptr ? v : "(null)");
  m += "\n";
  sink(std::move(m));
}
}  // namespace fuzzuf::utils
