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
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <boost/format.hpp>

#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/python/pyfeedback.hpp"
#include "fuzzuf/python/pyseed.hpp"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/status.hpp"

namespace py = pybind11;

#if (PYBIND11_VERSION_MAJOR == 2 && PYBIND11_VERSION_MINOR >= 2) || \
    PYBIND11_VERSION_MAJOR > 2
PYBIND11_MODULE(fuzzuf, f) {
#else
PYBIND11_PLUGIN(fuzzuf) {
  py::module f("fuzzuf");
#endif
  f.attr("INVALID_SEED_ID") =
      py::int_(fuzzuf::exec_input::ExecInput::INVALID_INPUT_ID);

  py::class_<fuzzuf::bindings::python::PySeed>(f, "Seed")
      .def(py::init<u64, std::vector<u8>,
                    std::optional<std::unordered_map<int, u8>>,
                    std::optional<std::unordered_map<int, u8>>>())
      .def("get_id", &fuzzuf::bindings::python::PySeed::GetID)
      .def("get_buf", &fuzzuf::bindings::python::PySeed::GetBuf)
      .def("get_feedback", &fuzzuf::bindings::python::PySeed::GetFeedback)
      .def("__repr__", [](const fuzzuf::bindings::python::PySeed &self) {
        return fuzzuf::utils::StrPrintf("Seed(id=%ld, ...)", self.GetID());
      });

  // 後方互換性のためPython側の"get_trace"という古い名前はget_bb_traceにしない（一旦）
  py::class_<fuzzuf::bindings::python::PyFeedback>(f, "Feedback")
      .def(py::init<std::optional<std::unordered_map<int, u8>>,
                    std::optional<std::unordered_map<int, u8>>>())
      .def("get_trace", &fuzzuf::bindings::python::PyFeedback::GetBBTrace)
      .def("get_afl_trace", &fuzzuf::bindings::python::PyFeedback::GetAFLTrace)
      .def("__repr__", [](const fuzzuf::bindings::python::PyFeedback &) {
        return "Feedback(TBD)";
      });

  // 後方互換性のためPython側の"get_traces"という古い名前はget_bb_tracesにしない（一旦）
  py::class_<fuzzuf::bindings::python::PythonFuzzer>(f, "Fuzzer")
      .def(py::init<const std::vector<std::string> &, std::string, std::string,
                    u32, u32, bool, bool, bool>())
      .def("flip_bit", &fuzzuf::bindings::python::PythonFuzzer::FlipBit)
      .def("flip_byte", &fuzzuf::bindings::python::PythonFuzzer::FlipByte)
      .def("havoc", &fuzzuf::bindings::python::PythonFuzzer::Havoc)
      .def("add", &fuzzuf::bindings::python::PythonFuzzer::Add)
      .def("sub", &fuzzuf::bindings::python::PythonFuzzer::Sub)
      .def("interest", &fuzzuf::bindings::python::PythonFuzzer::Interest)
      .def("overwrite", &fuzzuf::bindings::python::PythonFuzzer::Overwrite)
      .def("get_traces", &fuzzuf::bindings::python::PythonFuzzer::GetBBTraces)
      .def("get_afl_traces",
           &fuzzuf::bindings::python::PythonFuzzer::GetAFLTraces)
      .def("release", &fuzzuf::bindings::python::PythonFuzzer::Release)
      .def("reset", &fuzzuf::bindings::python::PythonFuzzer::Reset)
      .def("suppress_log", &fuzzuf::bindings::python::PythonFuzzer::SuppressLog)
      .def("show_log", &fuzzuf::bindings::python::PythonFuzzer::ShowLog)
      .def("get_seed", &fuzzuf::bindings::python::PythonFuzzer::GetPySeed)
      .def("selectSeed", &fuzzuf::bindings::python::PythonFuzzer::SelectSeed)
      .def("remove_seed", &fuzzuf::bindings::python::PythonFuzzer::RemoveSeed)
      .def("add_seed", &fuzzuf::bindings::python::PythonFuzzer::AddSeed)
      .def("get_seed_ids", &fuzzuf::bindings::python::PythonFuzzer::GetSeedIDs)
      .def("__repr__",
           [](const fuzzuf::bindings::python::PythonFuzzer & /*f*/) {
             return "Fuzzer()";
           });
  f.def("init_logger", &fuzzuf::utils::init_logger);
  f.def("log", [](const std::string &tag, const std::string &data) -> bool {
    return fuzzuf::utils::log(std::string(tag), std::string(data)) ==
           fuzzuf::utils::status_t::OK;
  });
#if !((PYBIND11_VERSION_MAJOR == 2 && PYBIND11_VERSION_MINOR >= 2) || \
      PYBIND11_VERSION_MAJOR > 2)
  return f.ptr();
#endif
}
