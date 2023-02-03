add_library(
  fuzzuf_core_rezzuf
  STATIC
  rezzuf_fuzzer.cpp
  rezzuf_hierarflow_routines.cpp
  rezzuf_setting.cpp
  rezzuf_state.cpp
  rezzuf_testcase.cpp
)

target_include_directories(
  fuzzuf_core_rezzuf
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_rezzuf
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_rezzuf
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_rezzuf
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_rezzuf
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_aflplusplus
  fuzzuf_core_afl_common
)
