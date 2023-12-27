if(NOT FUZZUF_CC_ROOT)
  find_program( FUZZUF_CC_CC fuzzuf-cc )
  find_program( FUZZUF_CC_CXX fuzzuf-c++ )
  find_program( FUZZUF_CC_AFL_CC fuzzuf-afl-cc )
  find_program( FUZZUF_CC_AFL_CXX fuzzuf-afl-c++ )
  find_program( FUZZUF_CC_IJON_CC fuzzuf-ijon-cc )
else()
  find_program( FUZZUF_CC_CC fuzzuf-cc NO_DEFAULT_PATH PATHS ${FUZZUF_CC_ROOT}/ ${FUZZUF_CC_ROOT}/bin/ )
  find_program( FUZZUF_CC_CXX fuzzuf-c++ NO_DEFAULT_PATH PATHS ${FUZZUF_CC_ROOT}/ ${FUZZUF_CC_ROOT}/bin/ )
  find_program( FUZZUF_CC_AFL_CC fuzzuf-afl-cc NO_DEFAULT_PATH PATHS ${FUZZUF_CC_ROOT}/ ${FUZZUF_CC_ROOT}/bin/ )
  find_program( FUZZUF_CC_AFL_CXX fuzzuf-afl-c++ NO_DEFAULT_PATH PATHS ${FUZZUF_CC_ROOT}/ ${FUZZUF_CC_ROOT}/bin/ )
  find_program( FUZZUF_CC_IJON_CC fuzzuf-ijon-cc NO_DEFAULT_PATH PATHS ${FUZZUF_CC_ROOT}/ ${FUZZUF_CC_ROOT}/bin/ )
endif()
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  FUZZUF_CC
  REQUIRED_VARS FUZZUF_CC_CC FUZZUF_CC_CXX FUZZUF_CC_AFL_CC FUZZUF_CC_AFL_CXX FUZZUF_CC_IJON_CC
)

