add_executable( test-nautilus-newtypes newtypes.cpp )
target_link_libraries(
  test-nautilus-newtypes
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-nautilus-newtypes
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-nautilus-newtypes
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-nautilus-newtypes
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_HEAVY_TEST )
add_test( NAME "nautilus.newtypes" COMMAND test-nautilus-newtypes )
endif()

add_executable( test-nautilus-context context.cpp )
target_link_libraries(
  test-nautilus-context
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-nautilus-context
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-nautilus-context
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-nautilus-context
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_HEAVY_TEST )
add_test( NAME "nautilus.context" COMMAND test-nautilus-context )
endif()

add_executable( test-nautilus-tree tree.cpp )
target_link_libraries(
  test-nautilus-tree
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-nautilus-tree
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-nautilus-tree
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-nautilus-tree
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_HEAVY_TEST )
add_test( NAME "nautilus.tree" COMMAND test-nautilus-tree )
endif()

add_executable( test-nautilus-mutator mutator.cpp )
target_link_libraries(
  test-nautilus-mutator
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-nautilus-mutator
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-nautilus-mutator
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-nautilus-mutator
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_HEAVY_TEST )
add_test( NAME "nautilus.mutator" COMMAND test-nautilus-mutator )
endif()

add_executable( test-nautilus-chunkstore chunkstore.cpp )
target_link_libraries(
  test-nautilus-chunkstore
  test-common
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::unit_test_framework
)
target_include_directories(
  test-nautilus-chunkstore
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/test/common
)
set_target_properties(
  test-nautilus-chunkstore
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  test-nautilus-chunkstore
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
if( ENABLE_HEAVY_TEST )
add_test( NAME "nautilus.chunkstore" COMMAND test-nautilus-chunkstore )
endif()
