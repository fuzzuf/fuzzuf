if( FUZZUF_CC_FOUND )
add_subdirectory(
  ijon
)
endif()
if( FUZZUF_CC_FOUND )
add_subdirectory(
  afl
)
endif()
add_subdirectory(
  afl-gcc
)
