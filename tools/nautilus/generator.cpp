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
 * @file generator.cpp
 * @brief Generate strings using a grammar.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <boost/program_options.hpp>

#include "fuzzuf/algorithms/nautilus/fuzzer/fuzzer.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/context.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/rule.hpp"
#include "fuzzuf/algorithms/nautilus/grammartec/tree.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace po = boost::program_options;
using namespace fuzzuf::algorithm::nautilus::fuzzer;
using namespace fuzzuf::algorithm::nautilus::grammartec;

int main(int argc, char** argv) {
  std::string grammar;
  fs::path grammar_path;
  size_t tree_depth, number_of_trees;
  bool store, verbose;

  try {
    po::options_description desc("Options");
    desc.add_options()("help,h", "Show this help")(
        "grammar_path,g",
        po::value<std::string>(&grammar)->value_name("GRAMMAR")->required(),
        "Path to grammar")(
        "tree_depth,t",
        po::value<size_t>(&tree_depth)->value_name("DEPTH")->required(),
        "Size of trees that are generated")(
        "number_of_trees,n",
        po::value<size_t>(&number_of_trees)
            ->value_name("NUMBER")
            ->default_value(1),
        "Number of trees to generate [default: 1]")(
        "store,s", po::bool_switch(&store),
        "Store output to files. This will create a folder called corpus "
        "containing one file for each generated tree.")(
        "verbose,v", po::bool_switch(&verbose), "Be verbose");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help") != 0U) {
      /* Show help message*/
      std::cout << desc << std::endl;
      std::exit(0);
    }

    po::notify(vm);

  } catch (std::exception& e) {
    /* Error on parsing arguments */
    std::cerr << "[-] Error: " << e.what() << std::endl;
    std::exit(1);
  }

  Context ctx;
  NautilusFuzzer::LoadGrammar(ctx, grammar);

  ctx.Initialize(tree_depth);

  /* Create corpus directory */
  if (store && !fs::exists("corpus")) {
    fs::create_directory("corpus");
  }

  /* Generate tree */
  for (size_t i = 0; i < number_of_trees; i++) {
    NTermID nonterm(ctx.NTID("START"));
    size_t len = ctx.GetRandomLenForNT(nonterm);
    Tree generated_tree = ctx.GenerateTreeFromNT(nonterm, len);

    if (verbose) {
      std::cout << "Generating tree " << i + 1 << " from " << number_of_trees
                << std::endl;
    }

    std::string buffer;
    generated_tree.UnparseTo(ctx, buffer);

    if (store) {
      /* Write to file */
      int fd =
          fuzzuf::utils::OpenFile(fuzzuf::utils::StrPrintf("corpus/%ld", i + 1),
                                  O_WRONLY | O_CREAT | O_TRUNC,
                                  S_IWUSR | S_IRUSR  // 0600
          );
      fuzzuf::utils::WriteFile(fd, buffer.data(), buffer.size());
      fuzzuf::utils::CloseFile(fd);

    } else {
      /* Write to stdout */
      std::cout << buffer << std::endl;
    }
  }
}
