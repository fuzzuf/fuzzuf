add_executable( test-proxy-executor-run run.cpp )
target_link_libraries(
  test-proxy-executor-run
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-proxy-executor-run
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-proxy-executor-run
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-proxy-executor-run
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_test(
  NAME "proxy_executor.run"
  COMMAND test-proxy-executor-run
)
