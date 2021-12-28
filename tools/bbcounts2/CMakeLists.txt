if(PIN_FOUND)
add_library(
  bbcounts2
  SHARED
  ${PIN_LIBRARY}
  bbcounts2.cpp
)
target_link_libraries(
  bbcounts2
  ${PIN_LIBRARIES}
)
target_include_directories(
  bbcounts2
  PRIVATE
  ${PIN_INCLUDE_DIRS}
)
if( ${CMAKE_VERSION} VERSION_LESS 3.13.0 )
link_directories(
  ${PIN_LIBRARY_DIRS}
)
else()
target_link_directories(
  bbcounts2
  PRIVATE
  ${PIN_LIBRARY_DIRS}
)
endif()
target_compile_definitions(
  bbcounts2
  PRIVATE
  ${PIN_DEFINITIONS}
)
set_target_properties(
  bbcounts2
  PROPERTIES COMPILE_FLAGS
  "${PIN_COMPILE_FLAGS}"
)
set_target_properties(
  bbcounts2
  PROPERTIES LINK_FLAGS
  "${PIN_LINK_FLAGS}"
)
set_target_properties(
  bbcounts2
  PROPERTIES
  CXX_CLANG_TIDY ""
)
set_target_properties( bbcounts2 PROPERTIES PREFIX "" )
endif()
