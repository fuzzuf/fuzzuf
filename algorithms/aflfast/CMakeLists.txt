add_library(
  fuzzuf_core_aflfast
  STATIC
  aflfast_other_hierarflow_routines.cpp
  aflfast_setting.cpp
  aflfast_state.cpp
  aflfast_testcase.cpp
)

target_include_directories(
  fuzzuf_core_aflfast
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_aflfast
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_aflfast
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_aflfast
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_aflfast
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)


