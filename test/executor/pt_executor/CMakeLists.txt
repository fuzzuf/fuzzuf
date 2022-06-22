if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  add_executable( test-pt-executor-run run.cpp )
  target_link_libraries(
    test-pt-executor-run
    test-common
    fuzzuf_core
    ${FUZZUF_LIBRARIES}
    Boost::unit_test_framework
  )
  target_include_directories(
    test-pt-executor-run
    PRIVATE
    ${FUZZUF_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/test/common
  )
  set_target_properties(
    test-pt-executor-run
    PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
  )
  set_target_properties(
    test-pt-executor-run
    PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
  )
endif()

if(PT_PROXY_FOUND)
  add_test(
    NAME "pt_executor.run"
    COMMAND sudo -E $<TARGET_FILE:test-pt-executor-run>
  )
endif()
