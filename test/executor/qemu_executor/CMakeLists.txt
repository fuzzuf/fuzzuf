add_executable( test-qemu-executor-run run.cpp )
target_link_libraries(
  test-qemu-executor-run
  test-common
  fuzzuf_core
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-qemu-executor-run
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-qemu-executor-run
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-qemu-executor-run
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)
if(QEMU_FOUND)
  add_test(
    NAME "qemu_executor.run"
    COMMAND test-qemu-executor-run
  )
endif()
