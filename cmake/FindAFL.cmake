if(NOT AFL_ROOT)
  find_program( AFL_CC afl-gcc )
  find_program( AFL_CXX afl-g++ )
else()
  find_program( AFL_CC afl-gcc NO_DEFAULT_PATH PATHS ${AFL_ROOT}/ ${AFL_ROOT}/bin/ )
  find_program( AFL_CXX afl-g++ NO_DEFAULT_PATH PATHS ${AFL_ROOT}/ ${AFL_ROOT}/bin/ )
endif()
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  AFL
  REQUIRED_VARS AFL_CC AFL_CXX
)

