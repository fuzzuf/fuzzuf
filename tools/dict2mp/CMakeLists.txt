add_executable( dict2mp dict2mp.cpp )
target_link_libraries(
  dict2mp
  fuzzuf
  ${FUZZUF_LIBRARIES}
  Boost::system
  Boost::program_options
)
target_include_directories(
  dict2mp
  PRIVATE
  ${FUZZUF_INCLUDE_DIRS}
)
set_target_properties(
  dict2mp
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  dict2mp
  PROPERTIES LINK_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)

