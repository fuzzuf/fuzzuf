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
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/python/pyfeedback.hpp"
#include "fuzzuf/python/pyseed.hpp"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/status.hpp"

#include <boost/format.hpp>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

#if (PYBIND11_VERSION_MAJOR == 2 && PYBIND11_VERSION_MINOR >= 2) ||            \
    PYBIND11_VERSION_MAJOR > 2
PYBIND11_MODULE(fuzzuf, f) {
#else
PYBIND11_PLUGIN(fuzzuf) {
  py::module f("fuzzuf");
#endif
  f.attr("INVALID_SEED_ID") = py::int_(ExecInput::INVALID_INPUT_ID);

  py::class_<PySeed>(f, "Seed")
      .def(py::init<u64, std::vector<u8>,
                    std::optional<std::unordered_map<int, u8>>,
                    std::optional<std::unordered_map<int, u8>>>())
      .def("get_id", &PySeed::GetID)
      .def("get_buf", &PySeed::GetBuf)
      .def("get_feedback", &PySeed::GetFeedback)
      .def("__repr__", [](const PySeed &self) {
        return Util::StrPrintf("Seed(id=%ld, ...)", self.GetID());
      });

  // 後方互換性のためPython側の"get_trace"という古い名前はget_bb_traceにしない（一旦）
  py::class_<PyFeedback>(f, "Feedback")
      .def(py::init<std::optional<std::unordered_map<int, u8>>,
                    std::optional<std::unordered_map<int, u8>>>())
      .def("get_trace", &PyFeedback::GetBBTrace)
      .def("get_afl_trace", &PyFeedback::GetAFLTrace)
      .def("__repr__", [](const PyFeedback &) { return "Feedback(TBD)"; });

  // 後方互換性のためPython側の"get_traces"という古い名前はget_bb_tracesにしない（一旦）
  py::class_<PythonFuzzer>(f, "Fuzzer")
      .def(py::init<const std::vector<std::string> &, std::string, std::string,
                    u32, u32, bool, bool, bool>())
      .def("flip_bit", &PythonFuzzer::FlipBit)
      .def("flip_byte", &PythonFuzzer::FlipByte)
      .def("havoc", &PythonFuzzer::Havoc)
      .def("add", &PythonFuzzer::Add)
      .def("sub", &PythonFuzzer::Sub)
      .def("interest", &PythonFuzzer::Interest)
      .def("overwrite", &PythonFuzzer::Overwrite)
      .def("get_traces", &PythonFuzzer::GetBBTraces)
      .def("get_afl_traces", &PythonFuzzer::GetAFLTraces)
      .def("release", &PythonFuzzer::Release)
      .def("reset", &PythonFuzzer::Reset)
      .def("suppress_log", &PythonFuzzer::SuppressLog)
      .def("show_log", &PythonFuzzer::ShowLog)
      .def("get_seed", &PythonFuzzer::GetPySeed)
      .def("selectSeed", &PythonFuzzer::SelectSeed)
      .def("remove_seed", &PythonFuzzer::RemoveSeed)
      .def("add_seed", &PythonFuzzer::AddSeed)
      .def("get_seed_ids", &PythonFuzzer::GetSeedIDs)
      .def("__repr__", [](const PythonFuzzer & /*f*/) { return "Fuzzer()"; });
  f.def("init_logger", &Util::init_logger);
  f.def("log", [](const std::string &tag, const std::string &data) -> bool {
    return Util::log(std::string(tag), std::string(data)) ==
           fuzzuf::status_t::OK;
  });
#if !((PYBIND11_VERSION_MAJOR == 2 && PYBIND11_VERSION_MINOR >= 2) ||          \
      PYBIND11_VERSION_MAJOR > 2)
  return f.ptr();
#endif
}
