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
#pragma once

#include <vector>
#include <string>
#include <memory>
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

#include "fuzzuf/python/python_state.hpp"
#include "fuzzuf/python/pyseed.hpp"
#include "fuzzuf/python/pyfeedback.hpp"
#include "fuzzuf/python/python_hierarflow_routines.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"

class PythonFuzzer : public Fuzzer {
public:
    explicit PythonFuzzer(
        const std::vector<std::string> &argv,
        const std::string &in,
        const std::string &out,
        u32 tmout,
        u32 memlimit,
        bool forksrv,
        bool need_afl_cov,
        bool need_bb_cov
    );
    ~PythonFuzzer();

    void BuildFuzzFlow(void);

    void ReceiveStopSignal(void);
    bool ShouldEnd(void) { return false; }

    void Reset(void);
    void Release(void);

    u64 FlipBit(u32 pos, u32 len);
    u64 FlipByte(u32 pos, u32 len);
    u64 Havoc(u32 stacking);
    u64 Add(u32 pos, int val, int bits, bool be);
    u64 Sub(u32 pos, int val, int bits, bool be);
    u64 Interest(u32 pos, int bits, int idx, bool be);
    u64 Overwrite(u32 pos, char chr);
    u64 AddSeed(u32 len, const std::vector<u8> &buf);

    void SelectSeed(u64 seed_id);
    void RemoveSeed(u64 seed_id);
    std::vector<u64> GetSeedIDs(void);
    std::optional<PySeed> GetPySeed(u64 seed_id);
    std::vector<std::unordered_map<int, u8>> GetBBTraces(void);
    std::vector<std::unordered_map<int, u8>> GetAFLTraces(void);
    
    void SuppressLog();
    void ShowLog();

private:
    void ExecuteInitialSeeds(const fs::path &in_dir);

    PythonSetting setting;
 
    using PyMutOutputType = fuzzuf::bindings::python::routine::PyMutOutputType;
    using PyUpdInputType = fuzzuf::bindings::python::routine::PyUpdInputType;

    HierarFlowNode<void(u32,u32), PyMutOutputType> bit_flip;
    HierarFlowNode<void(u32,u32), PyMutOutputType> byte_flip;
    HierarFlowNode<void(u32), PyMutOutputType> havoc;
    HierarFlowNode<void(u32,int,int,bool), PyMutOutputType> add;
    HierarFlowNode<void(u32,int,int,bool), PyMutOutputType> sub;
    HierarFlowNode<void(u32,int,u32,bool), PyMutOutputType> interest;
    HierarFlowNode<void(u32,char), PyMutOutputType> overwrite;
    HierarFlowNode<void(const u8*, u32), u64(const u8*, u32)> add_seed;

    // 以下はすべてPythonFuzzer::Reset用にunique_ptrになっている。別にResetがなければ例えばPythonState stateでいい
    std::unique_ptr<PythonState> state; 
    std::unique_ptr<fuzzuf::executor::NativeLinuxExecutor> executor;
};
