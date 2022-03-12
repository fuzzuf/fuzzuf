INSTALL(
  DIRECTORY fuzzuf/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/fuzzuf/
  FILES_MATCHING PATTERN "*.hpp"
)

### NOTE: Do not add `fuzzuf_cc`; Include files from fuzzuf_cc should be installed by fuzzuf-cc
###   Current implementation just aims to simplify fuzzuf-cc dependency.