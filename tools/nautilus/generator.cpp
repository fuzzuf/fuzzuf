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
 * @file generator.cpp
 * @brief Generate strings using a grammar.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <boost/program_options.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"


namespace po = boost::program_options;
using json = nlohmann::json;
using namespace fuzzuf::algorithm::nautilus::grammartec;

int main(int argc, char **argv) {
  std::string grammar;
  fs::path grammar_path;
  size_t tree_depth, number_of_trees;
  bool store, verbose;

  try {
    po::options_description desc("Options");
    desc.add_options()
      ("help,h", "Show this help")
      ("grammar_path,g",
       po::value<std::string>(&grammar)->value_name("GRAMMAR")->required(),
       "Path to grammar")
      ("tree_depth,t",
       po::value<size_t>(&tree_depth)->value_name("DEPTH")->required(),
       "Size of trees that are generated")
      ("number_of_trees,n",
       po::value<size_t>(&number_of_trees)->value_name("NUMBER")->default_value(1),
       "Number of trees to generate [default: 1]")
      ("store,s",
       po::bool_switch(&store),
       "Store output to files. This will create a folder called corpus containing one file for each generated tree.")
      ("verbose,v",
       po::bool_switch(&verbose),
       "Be verbose")
      ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help") != 0U) {
      /* Show help message*/
      std::cout << desc << std::endl;
      return 0;
    }

    po::notify(vm);

  } catch (std::exception& e) {
    /* Error on parsing arguments */
    std::cerr << "[-] Error: " << e.what() << std::endl;
    return 1;
  }

  Context ctx;
  grammar_path = grammar;

  /* Create new context and save it */
  if (grammar_path.extension() == ".json") {
    /* Check file */
    if (!fs::exists(grammar_path) || fs::is_directory(grammar_path)) {
      std::cerr << "[-] Grammar file does not exist or not a file." << std::endl
                << "    Path: " << grammar_path << std::endl;
      return 1;
    }

    /* Load JSON grammar */
    std::ifstream ifs(grammar_path);
    try {
      json j = json::parse(ifs);
      // TODO

    } catch (json::exception& e) {
      /* JSON parse error */
      std::cerr << "[-] Cannot parse grammar file" << std::endl
                << e.what() << std::endl;
      return 1;
    }

  } else if (grammar_path.extension() == ".py") {
    /* TODO: Support Python-written grammar */
    throw exceptions::not_implemented(
      "Grammar defined in Python is not supported yet", __FILE__, __LINE__
    );

  } else {
    throw exceptions::fuzzuf_runtime_error(
      "Unknown grammar type ('.json' expected)", __FILE__, __LINE__
    );
  }

  ctx.Initialize(tree_depth);
}
