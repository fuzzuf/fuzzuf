add_executable( test-mopt-loop loop.cpp )
target_link_libraries(
  test-mopt-loop
  test-common
  fuzzuf_core
  fuzzuf-cli-lib
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-mopt-loop
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-mopt-loop
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-mopt-loop
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if( ENABLE_CLANG_TIDY )
  set_target_properties(
    test-mopt-loop
    PROPERTIES
    CXX_CLANG_TIDY "${CLANG_TIDY};${CLANG_TIDY_CONFIG_FOR_TEST}"
  )
endif()
if( ENABLE_HEAVY_TEST )
add_test( NAME "mopt.loop" COMMAND test-mopt-loop )
endif()
