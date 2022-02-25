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
#include "fuzzuf/python/python_hierarflow_routines.hpp"

#include <random>
#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/executor/native_linux_executor.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/python/python_state.hpp"
#include "fuzzuf/logger/logger.hpp"

namespace fuzzuf::bindings::python::routine {

PyExecutePUT::PyExecutePUT(NativeLinuxExecutor& executor) : executor(executor) {}

NullableRef<HierarFlowCallee<PyMutOutputType>> PyExecutePUT::operator()(
    const u8* buf, u32 len
) {
    executor.Run(buf, len);
    auto exit_status = executor.GetExitStatusFeedback();
    auto afl_inp_feed = executor.GetAFLFeedback();
    auto  bb_inp_feed = executor.GetBBFeedback();
    SetResponseValue(
        CallSuccessors(buf, len, exit_status, afl_inp_feed, bb_inp_feed)
    );
    return GoToParent();
}

PyUpdate::PyUpdate(PythonState& state) : state(state) {} 

NullableRef<HierarFlowCallee<PyUpdInputType>> PyUpdate::operator()(
    const u8* buf,
    u32 len,
    ExitStatusFeedback exit_status,
    InplaceMemoryFeedback& afl_inp_feed,
    InplaceMemoryFeedback& bb_inp_feed
) {

    auto input = state.input_set.CreateOnMemory(buf, len);

    std::string fn;
    if ( exit_status.exit_reason == PUTExitReasonType::FAULT_TMOUT ) {
        fn = Util::StrPrintf("%s/hangs/%06u",
            state.setting.out_dir.c_str(), input->GetID());
    } else if ( exit_status.exit_reason == PUTExitReasonType::FAULT_CRASH ) {
        fn = Util::StrPrintf("%s/crashes/%06u",
            state.setting.out_dir.c_str(), input->GetID());
    } else {
        fn = Util::StrPrintf("%s/queue/id:%06u",
            state.setting.out_dir.c_str(), input->GetID());
    }

    input->SaveToFile(fn);

    // Currently, we do not push malformed inputs into the testcase set
    if ( exit_status.exit_reason == PUTExitReasonType::FAULT_TMOUT
      || exit_status.exit_reason == PUTExitReasonType::FAULT_CRASH ) {
        SetResponseValue(ExecInput::INVALID_INPUT_ID);
    } else {
        u64 id = input->GetID();
        SetResponseValue(id);

        state.test_set.emplace(id, 
            std::make_unique<PythonTestcase>(
                std::move(input),
                afl_inp_feed.ConvertToPersistent(),
                bb_inp_feed.ConvertToPersistent()
            )
        );
    }

    return GoToParent();
}

PyBitFlip::PyBitFlip(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32,u32)>> PyBitFlip::operator()(
    u32 pos, u32 len
) {
    auto& mutator = *state.mutator;

    if (len > 7) ERROR("BitFlip: 0 <= len < 8 must hold.");
    if (pos + len > mutator.GetLen()*8) ERROR("BitFlip: would be out of bounds.");

    mutator.FlipBit(pos, len);
    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

PyByteFlip::PyByteFlip(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32,u32)>> PyByteFlip::operator()(
    u32 pos, u32 len
) {
    auto& mutator = *state.mutator;

    if (len != 1 && len != 2 && len != 4) ERROR("ByteFlip: len should be 1, 2, or 4.");
    if (pos + len > mutator.GetLen()) ERROR("ByteFlip: would be out of bounds.");

    mutator.FlipByte(pos, len);
    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

PyHavoc::PyHavoc(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32)>> PyHavoc::operator()(u32 stacking) {
    auto& mutator = *state.mutator;

    if (stacking < 1 || 7 < stacking) ERROR("Havoc: 1 <= stack <= 7 must hold.");
    
    using algorithm::afl::util::AFLHavocCaseDistrib;
    using algorithm::afl::dictionary::AFLDictData;
    mutator.Havoc(1 << stacking, {}, {}, AFLHavocCaseDistrib, 
                  [](u32, u8*&, u32&, const std::vector<AFLDictData>&, const std::vector<AFLDictData>&){} );
    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

PyAdd::PyAdd(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32,int,int,bool)>> PyAdd::operator()(
    u32 pos, int val, int bits, bool be
) {
    auto& mutator = *state.mutator;

    if (bits == 8) {
        if (pos + 1 > mutator.GetLen()) ERROR("Add: would be out of bounds.");
        mutator.template AddN<u8>(pos, val, be);
    } else if (bits == 16) {
        if (pos + 2 > mutator.GetLen()) ERROR("Add: would be out of bounds.");
        mutator.template AddN<u16>(pos, val, be);
    } else if (bits == 32) {
        if (pos + 4 > mutator.GetLen()) ERROR("Add: would be out of bounds.");
        mutator.template AddN<u32>(pos, val, be);
    } else {
        ERROR("Add: bits should be 8, 16, or 32.");
    }

    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

PySub::PySub(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32,int,int,bool)>> PySub::operator()(
    u32 pos, int val, int bits, bool be
) {
    auto& mutator = *state.mutator;

    if (bits == 8) {
        if (pos + 1 > mutator.GetLen()) ERROR("Sub: would be out of bounds.");
        mutator.template SubN<u8>(pos, val, be);
    } else if (bits == 16) {
        if (pos + 2 > mutator.GetLen()) ERROR("Sub: would be out of bounds.");
        mutator.template SubN<u16>(pos, val, be);
    } else if (bits == 32) {
        if (pos + 4 > mutator.GetLen()) ERROR("Sub: would be out of bounds.");
        mutator.template SubN<u32>(pos, val, be);
    } else {
        ERROR("Sub: bits should be 8, 16, or 32.");
    }

    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

PyInterest::PyInterest(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32,int,u32,bool)>> PyInterest::operator()(
    u32 pos, int bits, u32 idx, bool be
) {
    auto& mutator = *state.mutator;

    if (bits == 8) {
        if (pos + 1 > mutator.GetLen()) ERROR("Interest: would be out of bounds.");
        if (idx >= Mutator<PythonTag>::interesting_8.size()) {
            ERROR("Interest: idx < %u must hold.\n", (u32)Mutator<PythonTag>::interesting_8.size());
        }

        mutator.template InterestN<u8>(pos, idx, be);
    } else if (bits == 16) {
        if (pos + 2 > mutator.GetLen()) ERROR("Interest: would be out of bounds.");
        if (idx >= Mutator<PythonTag>::interesting_16.size()) {
            ERROR("Interest: idx < %u must hold.\n", (u32)Mutator<PythonTag>::interesting_16.size());
        }

        mutator.template InterestN<u16>(pos, idx, be);
    } else if (bits == 32) {
        if (pos + 4 > mutator.GetLen()) ERROR("Interest: would be out of bounds.");
        if (idx >= Mutator<PythonTag>::interesting_32.size()) {
            ERROR("Interest: idx < %u must hold.\n", (u32)Mutator<PythonTag>::interesting_32.size());
        }
        mutator.template InterestN<u32>(pos, idx, be);
    } else {
        ERROR("Interest: bits should be 8, 16, or 32.");
    }

    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

PyOverwrite::PyOverwrite(PythonState& state) : state(state) {}

NullableRef<HierarFlowCallee<void(u32,char)>> PyOverwrite::operator()(
    u32 pos, char chr
) {
    auto& mutator = *state.mutator;

    if (pos >= mutator.GetLen()) ERROR("Overwrite: would be out of bounds.");

    mutator.Overwrite<char>(pos, chr);
    CallSuccessors(mutator.GetBuf(), mutator.GetLen());
    return GoToParent();
}

} // namespace fuzzuf::bindings::python::routine
