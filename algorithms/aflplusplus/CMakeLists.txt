add_library(
  fuzzuf_core_aflplusplus
  STATIC
  aflplusplus_havoc.cpp
  aflplusplus_mutation_hierarflow_routines.cpp
  aflplusplus_other_hierarflow_routines.cpp
  aflplusplus_setting.cpp
  aflplusplus_state.cpp
  aflplusplus_testcase.cpp
)

target_include_directories(
  fuzzuf_core_aflplusplus
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_aflplusplus
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_aflplusplus
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_aflplusplus
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_aflplusplus
  ${FUZZUF_LIBRARIES}
  fuzzuf_core_afl_common
)


