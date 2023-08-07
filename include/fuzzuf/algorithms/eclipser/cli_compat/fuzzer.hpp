/*
 * fuzzuf
 * Copyright (C) 2023 Ricerca Security
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
 * @file fuzzer.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHM_ECLIPSER_FUZZER_HPP
#define FUZZUF_INCLUDE_ALGORITHM_ECLIPSER_FUZZER_HPP

#include <chrono>
#include <cstddef>
#include <functional>
#include <random>
#include <variant>
#include <vector>

#include "fuzzuf/algorithms/eclipser/core/options.hpp"
#include "fuzzuf/cli/fuzzer_args.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/utils/node_tracer.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/replace_return_type.hpp"

namespace fuzzuf::cli {
struct GlobalFuzzerOptions;
}

namespace fuzzuf::algorithm::eclipser {

class EclipserFuzzer : public fuzzer::Fuzzer {
 public:
  EclipserFuzzer(cli::FuzzerArgs &, const cli::GlobalFuzzerOptions &,
              std::function<void(std::string &&)> &&);
  virtual ~EclipserFuzzer() {}
  virtual void OneLoop();
  virtual void ReceiveStopSignal(void) {}
  bool ShouldEnd() override { return end_; }
  const options::FuzzOption &GetOption() const { return opts; }
 private:
  bool end_ = false;
  options::FuzzOption opts;
};
}  // namespace fuzzuf::algorithm::eclipser

#endif
