/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
 * @file VUzzerMutator.hpp
 * @brief Mutation methods of VUzzer
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#pragma once

#include <cassert>
#include <random>

#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/algorithms/vuzzer/vuzzer_state.hpp"

namespace fuzzuf::algorithm::vuzzer {

// NOTE: VUzzerMutator is not "fully" inherited from Mutator
// Mutator's member functions are not virtual. 
// Hence you must not treat this as Mutator instance

class VUzzerMutator : public Mutator<VUzzerState::Tag> {
private:
    typedef void (VUzzerMutator::*MutFunc)(void);
    typedef std::pair<std::shared_ptr<ExecInput>, std::shared_ptr<ExecInput>> (VUzzerMutator::*MutCrossFunc)(const ExecInput&);
    static const MutFunc mutators[];
    static const MutCrossFunc crossovers[];
    
    // change at most 0-2 % of the binary with each fuzz
    // TODO: Set demoniator by constructor
    u32 denominator = 50;
    u32 int_slide_pos = 0;
    u32 slide_step = 1;
protected:
    const VUzzerState &state;

public:
    VUzzerMutator(const VUzzerMutator&) = delete;
    VUzzerMutator(VUzzerMutator&) = delete;

    // ムーブコンストラクタ
    VUzzerMutator(VUzzerMutator&&);

    VUzzerMutator( const ExecInput&, const VUzzerState& );
    ~VUzzerMutator();

    u32 GetCutPos(u32);

    void EliminateRandom();
    void EliminateRandomEnd();
    void DoubleEliminate();
    void AddRandom();
    void ChangeRandom();
    void ChangeBytes();
    void ChangeRandomFull();
    void SingleChangeRandom();
    void LowerSingleRandom();
    void RaiseSingleRandom();
    void EliminateNull();
    void EliminateDoubleNull();
    void TotallyRandom();
    void IntSlide();
    void DoubleFuzz();
    void DoubleFullMutate();

    void TaintBasedChange();

    void InsertWithOnebyteOverwrite(u32 pos, const u8 *buf, u32 extra_len);

    std::pair<std::shared_ptr<ExecInput>, std::shared_ptr<ExecInput>> SingleCrossOver(const ExecInput& target);
    std::pair<std::shared_ptr<ExecInput>, std::shared_ptr<ExecInput>> DoubleCrossOver(const ExecInput& target);
    std::pair<std::shared_ptr<ExecInput>, std::shared_ptr<ExecInput>> CrossOver(const ExecInput& target);
    void MutateRandom();
};

} // namespace fuzzuf::algorithm::vuzzer
