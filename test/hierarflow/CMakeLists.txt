add_executable( test-hierarflow-check-operator-behavior check_operator_behavior.cpp )
target_link_libraries(
  test-hierarflow-check-operator-behavior
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-hierarflow-check-operator-behavior
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-hierarflow-check-operator-behavior
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-hierarflow-check-operator-behavior
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_test( NAME "hierarflow.check_operator_behavior" COMMAND test-hierarflow-check-operator-behavior )

add_executable( test-hierarflow-handle-corner-cases handle_corner_cases.cpp )
target_link_libraries(
  test-hierarflow-handle-corner-cases
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-hierarflow-handle-corner-cases
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
# In this test, memory leaks will occur on purpose. So disable LeakSanitizer.
set_target_properties(
  test-hierarflow-handle-corner-cases
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR} -fno-sanitize=leak"
)
set_target_properties(
  test-hierarflow-handle-corner-cases
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR} -fno-sanitize=leak"
)
add_test( NAME "hierarflow.handle_corner_cases" COMMAND test-hierarflow-handle-corner-cases )

add_executable( test-hierarflow-utility utility.cpp )
target_link_libraries(
  test-hierarflow-utility
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-hierarflow-utility
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-hierarflow-utility
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-hierarflow-utility
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
add_test( NAME "hierarflow.utility" COMMAND test-hierarflow-utility )
