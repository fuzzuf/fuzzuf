if(NOT FUZZTOYS_ROOT)
  find_path( FUZZTOYS_DIR fuzz_toys-brainf_ck PATHS /usr/libexec/fuzz_toys /usr/local/libexec/fuzz_toys ${CMAKE_INSTALL_FULL_LIBEXECDIR}/fuzz_toys )
else()
  find_path( FUZZTOYS_DIR fuzz_toys-brainf_ck NO_DEFAULT_PATH PATHS ${FUZZTOYS_ROOT}/fuzz_toys ${FUZZTOYS_ROOT}/libexec/fuzz_toys )
endif()
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  FUZZTOYS
  REQUIRED_VARS FUZZTOYS_DIR
)

