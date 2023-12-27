if( FUZZUF_CC_FOUND )
add_subdirectory(
  ijon
)
add_subdirectory(
  afl
)
add_subdirectory(
  kscheduler
)
endif()

if( AFL_FOUND )
add_subdirectory(
  afl_gcc
)
add_subdirectory(
  nautilus
)
endif()
if( SYMCC_FOUND )
add_subdirectory(
  symcc
)
endif()
add_subdirectory(
  raw
)
