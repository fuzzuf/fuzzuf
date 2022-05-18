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

#include <memory>
#include "fuzzuf/python/python_state.hpp"

#include "fuzzuf/executor/native_linux_executor.hpp"

#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

namespace fuzzuf::bindings::python::routine {

using PyMutOutputType = u64(const u8*, u32);
using PyUpdInputType = u64(const u8*, 
                           u32, 
                           ExitStatusFeedback, 
                           InplaceMemoryFeedback&, 
                           InplaceMemoryFeedback&);

struct PyExecutePUT
    : public HierarFlowRoutine<
        PyMutOutputType,
        PyUpdInputType
      > {
public:
    PyExecutePUT(fuzzuf::executor::NativeLinuxExecutor &executor);

    NullableRef<HierarFlowCallee<PyMutOutputType>> operator()(const u8*, u32);

private:
    fuzzuf::executor::NativeLinuxExecutor &executor;
};

struct PyUpdate
    : public HierarFlowRoutine<
        PyUpdInputType,
        void(void)
      > {
public:
    PyUpdate(PythonState &state);

    NullableRef<HierarFlowCallee<PyUpdInputType>> operator()(
        const u8*,
        u32,
        ExitStatusFeedback,
        InplaceMemoryFeedback&,
        InplaceMemoryFeedback&
    );

private:
    PythonState &state;
};

struct PyBitFlip
    : public HierarFlowRoutine<
        void(u32,u32),
        PyMutOutputType
      > {
public:
    PyBitFlip(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32,u32)>> operator()(u32, u32);

private:
    PythonState &state;
};

struct PyByteFlip
    : public HierarFlowRoutine<
        void(u32,u32),
        PyMutOutputType
      > {
public:
    PyByteFlip(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32,u32)>> operator()(u32, u32);

private:
    PythonState &state;
};

struct PyHavoc
    : public HierarFlowRoutine<
        void(u32),
        PyMutOutputType
      > {
public:
    PyHavoc(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32)>> operator()(u32);

private:
    PythonState &state;
};

struct PyAdd
    : public HierarFlowRoutine<
        void(u32,int,int,bool),
        PyMutOutputType
      > {
public:
    PyAdd(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32,int,int,bool)>> operator()(
        u32, int, int, bool
    );

private:
    PythonState &state;
};

struct PySub
    : public HierarFlowRoutine<
        void(u32,int,int,bool),
        PyMutOutputType
      > {
public:
    PySub(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32,int,int,bool)>> operator()(
        u32, int, int, bool
    );

private:
    PythonState &state;
};


struct PyInterest
    : public HierarFlowRoutine<
        void(u32,int,u32,bool),
        PyMutOutputType
      > {
public:
    PyInterest(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32,int,u32,bool)>> operator()(
        u32, int, u32, bool
    );

private:
    PythonState &state;
};

struct PyOverwrite
    : public HierarFlowRoutine<
        void(u32,char),
        PyMutOutputType
      > {
public:
    PyOverwrite(PythonState &state);

    NullableRef<HierarFlowCallee<void(u32,char)>>operator()(u32, char);

private:
    PythonState &state;
};

} // namespace fuzzuf::bindings::python::routine
