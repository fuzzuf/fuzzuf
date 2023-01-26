add_library(
  fuzzuf_core_afl_common
  STATIC
  afl_dict_data.cpp
  afl_havoc_case_distrib.cpp
  afl_havoc_optimizer.cpp
  afl_setting.cpp
  afl_testcase.cpp
  afl_util.cpp
)

target_include_directories(
  fuzzuf_core_afl_common
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf_core_afl_common
  PROPERTIES
  POSITION_INDEPENDENT_CODE
  ON
)

set_target_properties(
  fuzzuf_core_afl_common
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf_core_afl_common
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf_core_afl_common
  ${FUZZUF_LIBRARIES}
  fuzzuf_core
)


