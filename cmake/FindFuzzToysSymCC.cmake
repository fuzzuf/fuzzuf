if (NOT FUZZTOYS_SYMCC_ROOT)
find_path(
  FUZZTOYS_SYMCC_DIR fuzz_toys-branch
  PATHS
  /usr/libexec/fuzz_toys_symcc
  /usr/local/libexec/fuzz_toys_symcc
  ${CMAKE_INSTALL_FULL_LIBEXECDIR}/fuzz_toys_symcc
)
else()
find_path(
  FUZZTOYS_SYMCC_DIR
  fuzz_toys-branch
  NO_DEFAULT_PATH
  PATHS
  ${FUZZTOYS_SYMCC_ROOT}/fuzz_toys_symcc
  ${FUZZTOYS_SYMCC_ROOT}/libexec/fuzz_toys_symcc
)
endif()
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  FUZZTOYS_SYMCC
  REQUIRED_VARS
  FUZZTOYS_SYMCC_DIR
)

