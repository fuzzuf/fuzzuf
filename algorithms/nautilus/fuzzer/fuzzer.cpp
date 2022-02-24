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
 * @file fuzzer.cpp
 * @brief Fuzzing loop of Nautilus.
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "fuzzuf/algorithms/nautilus/fuzzer/fuzzer.hpp"
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

using json = nlohmann::json;

/**
 * @fn
 * @brief Construct Nautilus fuzzer
 * @param (state_ref) Reference to the state of Nautilus fuzzer
 */
NautilusFuzzer::NautilusFuzzer(std::unique_ptr<NautilusState>&& state_ref)
  : state(std::move(state_ref)) {
  /* Check files and load grammar */
  CheckPathExistence();
  LoadGrammar();

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
  using fuzzuf::hierarflow::CreateNode;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::other;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::mutation;
  using namespace fuzzuf::algorithm::nautilus::fuzzer::routine::update;

  fuzz_loop = CreateNode<FuzzLoop>(*state);

  /* Main flow */
  auto select_input            = CreateNode<SelectInput>(*state);
  auto process_chosen_input_or = CreateNode<ProcessInput>(*state);
  auto generate_input          = CreateNode<GenerateInput>(*state);
  auto update_state            = CreateNode<UpdateState>(*state);

  /* Processing flow */
  auto initialize_state_or = CreateNode<InitializeState>(*state);
  auto apply_det_muts_or   = CreateNode<ApplyDetMuts>(*state);
  auto apply_rand_muts     = CreateNode<ApplyRandMuts>(*state);

  /* Mutation flow */
  auto mut_rules = CreateNode<MutRules>(*state);
  auto splice    = CreateNode<MutSplice>(*state);
  auto havoc     = CreateNode<MutHavoc>(*state);
  auto havoc_rec = CreateNode<MutHavocRec>(*state);

  fuzz_loop << (
    select_input << (
      process_chosen_input_or
      || generate_input // TODO: maybe execute.HardLink() here
    )
    || update_state
  );

  process_chosen_input_or << (
    initialize_state_or
    || apply_det_muts_or << (
      mut_rules
      || splice.HardLink()
      || havoc.HardLink()
      || havoc_rec.HardLink()
    )
    || apply_rand_muts << (
      splice.HardLink()
      || havoc.HardLink()
      || havoc_rec.HardLink()
    )
  );
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
      Util::StrPrintf("Target binary does not exist!\nGiven path: %s",
                      setting->args[0].c_str()),
      __FILE__, __LINE__
    );
  }

  // NOTE: this check might be unnecessary as NativeLinuxExecutor would die
  if (!fs::exists(setting->path_to_workdir)
      || !fs::is_directory(setting->path_to_workdir)) {
    throw exceptions::invalid_file(
      Util::StrPrintf("Specified working directory does not exist!\n"
                      "Given path: %s",
                      setting->path_to_workdir.c_str()),
      __FILE__, __LINE__
    );
  }

  /* Check grammar file path */
  if (!fs::exists(setting->path_to_grammar)) {
    throw exceptions::invalid_file(
      Util::StrPrintf("Grammar does not exist!\n"
                      "Given path: %s",
                      setting->path_to_grammar.c_str()),
      __FILE__, __LINE__
    );
  }

  /* Check output directories */
  std::vector<std::string> folders{"signaled", "queue", "timeout", "chunks"};
  for (auto f: folders) {
    fs::path dir = setting->path_to_workdir / f;
    if (!fs::exists(dir) || !fs::is_directory(dir)) {
      throw exceptions::execution_failure(
        Util::StrPrintf("Output directory does not exist: %s", dir.c_str()),
        __FILE__, __LINE__
      );
    }
  }
}

/**
 * @fn
 * @brief Load grammar file
 */
void NautilusFuzzer::LoadGrammar() {
  std::shared_ptr<const NautilusSetting> setting(state->setting);

  if (setting->path_to_grammar.extension() == ".json") {
    /* Load JSON grammar */
    std::ifstream ifs(setting->path_to_grammar.string());

    try {
      json rules = json::parse(ifs);

      /* Check JSON type */
      if (rules.type() != json::value_t::array) {
        throw exceptions::invalid_file(
          "Invalid rules (Rules must be array)", __FILE__, __LINE__
        );

      } else if (rules.size() == 0) {
        throw exceptions::invalid_file(
          "Rule file doesn't include any rules", __FILE__, __LINE__
        );

      } else if (rules[0].type() != json::value_t::array
                 || rules[0].size() != 2
                 || rules[0].get<json>()[0].type() != json::value_t::string) {
        throw exceptions::invalid_file(
          Util::StrPrintf("Invalid rule (Each rule must be a pair of string)\n",
                          "Rule: %s", rules[0].get<json>().dump().c_str()),
          __FILE__, __LINE__
        );
      }

      /* Add rules */
      std::string root = "{" +                                \
        rules[0].get<json>()[0].get_ref<std::string&>() +  \
        "}";
      state->ctx.AddRule("START", root);

      for (auto& rule: rules) {
        if (rule.type() != json::value_t::array
            || rule.size() != 2
            || rule[0].type() != json::value_t::string
            || rule[1].type() != json::value_t::string) {
          throw exceptions::invalid_file(
            Util::StrPrintf("Invalid rule (Each rule must be a pair of string)\n",
                            "Rule: %s", rule.dump().c_str()),
            __FILE__, __LINE__
          );
        }

        state->ctx.AddRule(
          rule[0].get<std::string>(), rule[1].get<std::string>()
        );
      }

    } catch (std::exception& e) {
      /* JSON parse error */
      throw exceptions::invalid_file(
        Util::StrPrintf("Cannot parse grammar file\n%s", e.what()),
        __FILE__, __LINE__
      );
    }

  } else if (setting->path_to_grammar.extension() == ".py") {
    /* TODO: Support Python-written grammar */
    throw exceptions::not_implemented(
      "Grammar defined in Python is not supported yet", __FILE__, __LINE__
    );

  } else {
    throw exceptions::fuzzuf_runtime_error(
      "Unknown grammar type ('.json' expected)", __FILE__, __LINE__
    );
  }

  /* Initialize context */
  state->ctx.Initialize(setting->max_tree_size);
}

/**
 * @fn
 * @brief Run fuzzing loop once
 */
void NautilusFuzzer::OneLoop(void) {
  fuzz_loop();
}

/**
 * @fn
 * @brief Receive stop signal
 */
void NautilusFuzzer::ReceiveStopSignal(void) {
  // TODO: comment out
  //state->ReceiveStopSignal();
}

/**
 * @fn
 * @brief Check if fuzzing should terminate
 * @return True if fuzzing ends, otherwise false
 */
bool NautilusFuzzer::ShouldEnd(void) {
  return false;
}

/**
 * @fn
 * @brief Destroy this instance
 */
NautilusFuzzer::~NautilusFuzzer() {
}

} // namespace fuzzuf::algorithm::nautilus
