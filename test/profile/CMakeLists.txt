add_executable( profile-add-seed add_seed.cpp )

target_link_libraries(
  profile-add-seed
  fuzzuf
  ${FUZZUF_LIBRARIES}
)

target_include_directories(
  profile-add-seed
  PRIVATE
  ${CMAKE_SOURCE_DIR}/Include
  ${CMAKE_BINARY_DIR}
  ${FUZZUF_INCLUDE_DIRS}
)
set_target_properties(
  profile-add-seed
  PROPERTIES COMPILE_FLAGS "${ADDITIONAL_COMPILE_FLAGS_STR}"
)
set_target_properties(
  profile-add-seed
  PROPERTIES LINK_FLAGS "${ADDITIONAL_LINK_FLAGS_STR}"
)

set(CMAKE_CXX_FLAGS "-pg -g")
