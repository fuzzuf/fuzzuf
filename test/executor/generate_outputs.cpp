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
#include <cstdlib>
#include <fstream>
#include <fuzzuf/utils/filesystem.hpp>

int main() {
  const auto val = std::getenv("OUTPUT_DIR");
  if (!val) std::abort();
  const auto outdir = fs::path(val);
  fs::create_directory(outdir);
  for (auto &filename : std::array<std::string, 3>{"foo", "bar", "moo"}) {
    if (fs::exists(outdir / filename)) std::abort();
    std::fstream f((outdir / filename).string(), std::ios::out);
    f << "Hello, " << filename << std::endl;
  }
}
