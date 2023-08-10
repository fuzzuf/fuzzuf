if( NOT DIE_BUILD_NPM )
add_custom_command(
  OUTPUT die-npm-installed
  COMMAND npm install npm@6.14.4 --prefix=${CMAKE_CURRENT_BINARY_DIR}/
  COMMAND touch die-npm-installed
  BYPRODUCTS node_modules die-npm-installed
  COMMENT "Installing npm-6.14.4..."
)
endif()

# Copy scripts to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/typer.py
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/build_die.sh
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Setup DIE
if( NOT DIE_BUILD_NPM )
add_custom_target(die
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/build_die.sh ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Setting up DIE..."
  BYPRODUCTS DIE/fuzz/TS/node_modules
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/build_die.sh die-npm-installed
  VERBATIM)
else()
add_custom_target(die
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/build_die.sh ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Setting up DIE..."
  BYPRODUCTS DIE/fuzz/TS/node_modules
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/build_die.sh
  VERBATIM)
endif()
