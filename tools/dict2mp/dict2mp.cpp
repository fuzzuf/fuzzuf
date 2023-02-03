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
#include <boost/program_options.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "fuzzuf/algorithms/libfuzzer/dictionary.hpp"

// Convert from an AFL dictionary format to an array of msgpack

int main(int argc, char *argv[]) {
  namespace po = boost::program_options;

  po::options_description desc("Options");
  std::string in_file("input.dict");
  std::string out_file("output.mp");
  bool strict = false;
  desc.add_options()("help,h", "show this message")(
      "input,i", po::value<std::string>(&in_file), "input filename")(
      "output,o", po::value<std::string>(&out_file), "output filename")(
      "strict,s", po::bool_switch(&strict), "strict mode");
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);
  if (vm.count("help") != 0U) {
    std::cout << desc << std::endl;
    exit(0);
  }

  fuzzuf::algorithm::libfuzzer::dictionary::StaticDictionary dict;
  Load(in_file, dict, strict,
       [](std::string &&m) { std::cerr << m << std::endl; });

  std::vector<uint8_t> temp;

  if (dict.size() < (size_t(1U) << 4)) {
    temp.push_back(0x90U | dict.size());
  } else if (dict.size() < (size_t(1U) << 16)) {
    temp.push_back(0xdcU);
    temp.push_back((dict.size() >> 8) & 0xFFU);
    temp.push_back(dict.size() & 0xFFU);
  } else if (dict.size() < (size_t(1U) << 32)) {
    temp.push_back(0xddU);
    temp.push_back((dict.size() >> 24) & 0xFFU);
    temp.push_back((dict.size() >> 16) & 0xFFU);
    temp.push_back((dict.size() >> 8) & 0xFFU);
    temp.push_back(dict.size() & 0xFFU);
  } else {
    std::cerr << "too many entries" << std::endl;
    exit(1);
  }

  for (const auto &v : dict) {
    const size_t size = v.get().size();
    if (size < (size_t(1U) << 8)) {
      temp.push_back(0xc4);
      temp.push_back(size);
    } else if (v.get().size() < (size_t(1U) << 16)) {
      temp.push_back(0xc5);
      temp.push_back((size >> 8) & 0xFFU);
      temp.push_back(size & 0xFFU);
    } else if (v.get().size() < (size_t(1U) << 32)) {
      temp.push_back(0xc6);
      temp.push_back((size >> 24) & 0xFFU);
      temp.push_back((size >> 16) & 0xFFU);
      temp.push_back((size >> 8) & 0xFFU);
      temp.push_back(size & 0xFFU);
    } else {
      std::cerr << "too long entry" << std::endl;
      exit(1);
    }
    temp.insert(temp.end(), v.get().begin(), v.get().end());
  }

  std::ofstream file(out_file);
  file.write(reinterpret_cast<const char *>(temp.data()), temp.size());
}
