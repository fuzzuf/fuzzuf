add_library(
  fuzzuf_core_ijon
  STATIC
  ijon_fuzzer.cpp
  ijon_havoc.cpp
  ijon_hierarflow_routines.cpp
  ijon_testcase.cpp
  ijon_state.cpp
)

target_include_directories(
  fuzzuf_core_ijon
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_ijon
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_ijon
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_ijon
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_ijon
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)



