add_library(
  fuzzuf_core_vuzzer
  STATIC
  vuzzer.cpp
  vuzzer_mutation_hierarflow_routines.cpp
  vuzzer_mutator.cpp
  vuzzer_other_hierarflow_routines.cpp
  vuzzer_setting.cpp
  vuzzer_state.cpp
  vuzzer_testcase.cpp
  vuzzer_update_hierarflow_routines.cpp
  vuzzer_util.cpp
)

target_include_directories(
  fuzzuf_core_vuzzer
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_vuzzer
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_vuzzer
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_vuzzer
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_vuzzer
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)


