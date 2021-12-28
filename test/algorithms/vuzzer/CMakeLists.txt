add_executable( test-vuzzer-loop loop.cpp )
target_link_libraries(
  test-vuzzer-loop
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-vuzzer-loop
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-vuzzer-loop
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-vuzzer-loop
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_HEAVY_TEST )
add_test( NAME "vuzzer.loop" COMMAND test-vuzzer-loop )
endif()
