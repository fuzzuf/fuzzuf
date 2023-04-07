algorithm_enabled(ENABLE_NAUTILUS "${ALGORITHMS}" nautilus)
if( ENABLE_NAUTILUS )
add_executable( generator generator.cpp )
target_link_libraries(
  generator
  fuzzuf_core
  fuzzuf_core_nautilus
  ${FUZZUF_LIBRARIES}
  Boost::system
  Boost::program_options
)
target_include_directories(
  generator
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)
set_target_properties(
  generator
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  generator
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
endif()

