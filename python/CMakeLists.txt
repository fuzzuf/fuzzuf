add_library(
  fuzzuf
  SHARED
  pyfeedback.cpp
  python_fuzzer.cpp
  python_setting.cpp
  python_testcase.cpp
  export_fuzzuf.cpp
  pyseed.cpp
  python_hierarflow_routines.cpp
  python_state.cpp
)

target_include_directories(
  fuzzuf
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)

set_target_properties(
  fuzzuf
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

set_target_properties(
  fuzzuf
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

target_link_libraries(
  fuzzuf
  ${FUZZUF_LIBRARIES}
  fuzzuf_core
  fuzzuf_core_afl_common
)

set_target_properties( fuzzuf PROPERTIES PREFIX "" )
set_target_properties( fuzzuf PROPERTIES SUFFIX ".${Python3_SOABI}${CMAKE_SHARED_LIBRARY_SUFFIX}" )
list( GET Python3_SITELIB 0 Python3_FIRST_SITELIB )
install( TARGETS fuzzuf LIBRARY DESTINATION "${Python3_FIRST_SITELIB}" )

