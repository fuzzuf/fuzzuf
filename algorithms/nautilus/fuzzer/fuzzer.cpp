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
 * @file fuzzer.cpp
 * @brief Fuzzing loop of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include "fuzzuf/algorithms/nautilus/fuzzer/fuzzer.hpp"

#include <algorithm>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "fuzzuf/algorithms/nautilus/fuzzer/mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/nautilus/fuzzer/update_hierarflow_routines.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/logger/logger.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/filesystem.hpp"

namespace fuzzuf::algorithm::nautilus::fuzzer {

/**
 * @fn
 * @brief Construct Nautilus fuzzer
 * @param (state_ref) Reference to the state of Nautilus fuzzer
 */
NautilusFuzzer::NautilusFuzzer(std::unique_ptr<NautilusState>&& state_ref)
    : state(std::move(state_ref)) {
  /* Check files */
  CheckPathExistence();

  /* Load grammar */
  NautilusFuzzer::LoadGrammar(state->ctx, state->setting->path_to_grammar);
  state->ctx.Initialize(state->setting->max_tree_size);

  /* Construct fuzzing loop */
  BuildFuzzFlow();

  /* Clear screen */
  MSG(TERM_CLEAR);
}

/**
 * @fn
 * @brief Build HierarFlow of Nautilus
 */
void NautilusFuzzer::BuildFuzzFlow() {
  using fuzzuf::hierarflow::CreateIrregularNode;
  using fuzzuf::hierarflow::CreateNode;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update;

  fuzz_loop = CreateNode<FuzzLoop>(*state);

  /* Mutation flow */
  auto mut_rules = CreateNode<MutRules>(*state);
  auto splice = CreateNode<MutSplice>(*state);
  auto havoc = CreateNode<MutHavoc>(*state);
  auto havoc_rec = CreateNode<MutHavocRec>(*state);

  /* Processing flow */
  auto initialize_state = CreateNode<InitializeState>(*state);
  auto apply_det_muts = CreateNode<ApplyDetMuts>(*state);
  auto apply_rand_muts = CreateNode<ApplyRandMuts>(*state);

  /* Main flow */
  auto process_next_input = CreateIrregularNode<ProcessInput>(
      *state, initialize_state.GetCalleeIndexRef(),
      apply_det_muts.GetCalleeIndexRef(), apply_rand_muts.GetCalleeIndexRef());
  auto generate_input = CreateNode<GenerateInput>(*state);
  auto select_input_and_switch = CreateIrregularNode<SelectInput>(
      *state, process_next_input.GetCalleeIndexRef(),
      generate_input.GetCalleeIndexRef());
  auto update_state = CreateNode<UpdateState>(*state);

  fuzz_loop << (select_input_and_switch <=
                    (process_next_input || generate_input) ||
                update_state);

  process_next_input <=
      (initialize_state ||
       apply_det_muts << (mut_rules || splice.HardLink() || havoc.HardLink() ||
                          havoc_rec.HardLink()) ||
       apply_rand_muts << (splice.HardLink() || havoc.HardLink() ||
                           havoc_rec.HardLink()));
}

/**
 * @fn
 * @brief Check if files specified in config exist
 */
void NautilusFuzzer::CheckPathExistence() {
  std::shared_ptr<const NautilusSetting> setting(state->setting);

  // NOTE: this check might be unnecessary as NativeLinuxExecutor would die
  if (!fs::exists(setting->args[0])) {
    throw exceptions::invalid_file(
        fuzzuf::utils::StrPrintf(
            "Target binary does not exist!\nGiven path: %s",
            setting->args[0].c_str()),
        __FILE__, __LINE__);
  }

  // NOTE: this check might be unnecessary as NativeLinuxExecutor would die
  if (!fs::exists(setting->path_to_workdir) ||
      !fs::is_directory(setting->path_to_workdir)) {
    throw exceptions::invalid_file(
        fuzzuf::utils::StrPrintf("Specified working directory does not exist!\n"
                                 "Given path: %s",
                                 setting->path_to_workdir.c_str()),
        __FILE__, __LINE__);
  }

  /* Check grammar file path */
  if (!fs::exists(setting->path_to_grammar)) {
    throw exceptions::invalid_file(
        fuzzuf::utils::StrPrintf("Grammar does not exist!\n"
                                 "Given path: %s",
                                 setting->path_to_grammar.c_str()),
        __FILE__, __LINE__);
  }

  /* Check output directories */
  std::vector<std::string> folders{"signaled", "queue", "timeout", "chunks"};
  for (auto f : folders) {
    fs::path dir = setting->path_to_workdir / f;
    if (!fs::exists(dir) || !fs::is_directory(dir)) {
      throw exceptions::execution_failure(
          fuzzuf::utils::StrPrintf("Output directory does not exist: %s",
                                   dir.c_str()),
          __FILE__, __LINE__);
    }
  }
}

/**
 * @fn
 * @brief Parse and add rules in JSON object
 * @param (ctx) Context
 * @param (nt) Nontermnal symbol
 * @param (rule) Rule for NT in JSON object
 * @param ()
 */
bool NautilusFuzzer::ParseAndAddRule(Context& ctx, std::string nt, json rule,
                                     bool recursive /*=false*/) {
  if (rule.is_string()) {
    /* Simple string rule: just add it */
    ctx.AddRule(nt, rule.get<std::string>());
    return true;

  } else if (rule.is_array()) {
    /* Array rule: Union or binary */

    /* Check if every rule is integer or string */
    bool has_integer = false;
    if (std::all_of(rule.begin(), rule.end(), [&has_integer](const json& e) {
          has_integer |= e.is_number_integer();
          return e.is_number_integer() || e.is_string();
        })) {
      if (!has_integer) {
        /* Union rule if every rule is string */
        for (const json& e : rule) {
          if (!NautilusFuzzer::ParseAndAddRule(ctx, nt, e, true)) {
            std::cerr << "[-] Invalid rule" << std::endl
                      << "    NT   : " << nt << std::endl
                      << "    RULES: " << rule << std::endl
                      << "    RULE : " << e << std::endl;
            std::exit(1);
          }
        }
        return true;

      } else {
        /* This is a binary rule */
        std::string r;
        for (const json& e : rule) {
          if (e.is_string()) {
            /* Simply concat string */
            r += e.get<std::string>();

          } else {
            /* Read as a character code */
            size_t c = e.get<size_t>();
            if (c >= 0x100) {
              std::cerr << "[-] Invalid character code" << std::endl
                        << "    NT  : " << nt << std::endl
                        << "    RULE: " << rule << std::endl
                        << "    The value " << c << " is out-of-range."
                        << std::endl;
              std::exit(1);
            }

            r.push_back((char)c);
          }
        }

        ctx.AddRule(nt, r);
        return true;
      }

    } else if (!recursive) {
      /* Union rule with binary rule inside */
      for (const json& e : rule) {
        if (!NautilusFuzzer::ParseAndAddRule(ctx, nt, e, true)) {
          std::cerr << "[-] Invalid rule" << std::endl
                    << "    NT   : " << nt << std::endl
                    << "    RULES: " << rule << std::endl
                    << "    RULE : " << e << std::endl;
          std::exit(1);
        }
      }
      return true;

    } else {
      /* Invalid recursive array */
      return false;
    }
  }

  /* Invalid type */
  std::cerr << "[-] Invalid rule" << std::endl
            << "    NT  : " << nt << std::endl
            << "    RULE: " << rule << std::endl;
  std::exit(1);
}

/**
 * @fn
 * @brief Load grammar written in the grammar file
 * @param (ctx) Context
 * @param (grammar_path) Path to the grammar file
 */
void NautilusFuzzer::LoadGrammar(Context& ctx, fs::path grammar_path) {
  /* Create new context and save it */
  if (grammar_path.extension() == ".json") {
    /* Check file */
    if (!fs::exists(grammar_path) || fs::is_directory(grammar_path)) {
      std::cerr << "[-] Grammar file does not exist or not a file." << std::endl
                << "    Path: " << grammar_path << std::endl;
      std::exit(1);
    }

    /* Load JSON grammar */
    std::ifstream ifs(grammar_path.string());
    try {
      json rules = json::parse(ifs);

      if (!rules.is_array()) {
        std::cerr << "[-] Invalid rules (Rules must be array)" << std::endl;
        std::exit(1);
      } else if (rules.size() == 0) {
        std::cerr << "[-] Rule file doesn't include any rules" << std::endl;
        std::exit(1);
      } else if (!rules[0].is_array() || rules[0].size() != 2 ||
                 !rules[0].get<json>()[0].is_string()) {
        std::cerr << "[-] First rule is invalid" << std::endl
                  << "    It must be an array with 2 elements. The first"
                  << std::endl
                  << "    one must be  a string representing the name"
                  << std::endl
                  << "    of the nonterminal." << std::endl;
        std::exit(1);
      }

      /* Add rules */
      std::string root = "{" + rules[0].get<json>()[0].get<std::string>() + "}";
      NautilusFuzzer::ParseAndAddRule(ctx, "START", root);

      for (auto& rule : rules) {
        if (!rule.is_array() || rule.size() != 2 || !rule[0].is_string()) {
          std::cerr << "[-] Invalid rule" << std::endl
                    << "    It must be an array with 2 elements. The first"
                    << std::endl
                    << "    one must be  a string representing the name"
                    << std::endl
                    << "    of the nonterminal." << std::endl;
          std::cerr << "    RULE: " << rule << std::endl;
          std::exit(1);
        }

        NautilusFuzzer::ParseAndAddRule(ctx, rule[0].get<std::string>(),
                                        rule[1].get<json>());
      }

    } catch (std::exception& e) {
      /* JSON parse error */
      std::cerr << "[-] Cannot parse grammar file" << std::endl
                << e.what() << std::endl;
      std::exit(1);
    }

  } else if (grammar_path.extension() == ".py") {
    /* TODO: Support Python-written grammar */
    throw exceptions::not_implemented(
        "Grammar defined in Python is not supported yet", __FILE__, __LINE__);

  } else {
    throw exceptions::fuzzuf_runtime_error(
        "Unknown grammar type ('.json' expected)", __FILE__, __LINE__);
  }
}

/**
 * @fn
 * @brief Run fuzzing loop once
 */
void NautilusFuzzer::OneLoop(void) { fuzz_loop(); }

/**
 * @fn
 * @brief Receive stop signal
 */
void NautilusFuzzer::ReceiveStopSignal(void) {
  // TODO: comment out
  // state->ReceiveStopSignal();
}

/**
 * @fn
 * @brief Check if fuzzing should terminate
 * @return True if fuzzing ends, otherwise false
 */
bool NautilusFuzzer::ShouldEnd(void) { return false; }

/**
 * @fn
 * @brief Destroy this instance
 */
NautilusFuzzer::~NautilusFuzzer() {}

}  // namespace fuzzuf::algorithm::nautilus::fuzzer
