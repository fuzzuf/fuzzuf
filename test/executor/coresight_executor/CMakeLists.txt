if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
  add_executable( test-coresight-executor-run run.cpp )
  target_link_libraries(
    test-coresight-executor-run
    test-common
    fuzzuf_core
    ${FUZZUF_LIBRARIES}
    Boost::unit_test_framework
  )
  target_include_directories(
    test-coresight-executor-run
    PRIVATE
    ${FUZZUF_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/test/common
  )
  set_target_properties(
    test-coresight-executor-run
    PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
  )
  set_target_properties(
    test-coresight-executor-run
    PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
  )
endif()

if(CORESIGHT_TRACE_FOUND)
  add_test(
    NAME "coresight_executor.run"
    COMMAND sudo -E $<TARGET_FILE:test-coresight-executor-run>
  )
  set_tests_properties(
    "coresight_executor.run"
    PROPERTIES ENVIRONMENT AFLCS_NO_FORKSRV=1
  )
endif()
