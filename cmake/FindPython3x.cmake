#
# fuzzuf
# Copyright (C) 2021-2023 Ricerca Security
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.
#
find_package( Threads REQUIRED )
if( NOT Python3_FOUND )
  execute_process(
    COMMAND pyenv version-name
    OUTPUT_VARIABLE PATTR_PYENV
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ENCODING AUTO
  )
  if( "${PATTR_PYENV}" STREQUAL "system" )
    set( PATTR_PYENV "native" )
  elseif( "${PATTR_PYENV}" STREQUAL "" )
    set( PATTR_PYENV "native" )
  endif()
  string(REGEX REPLACE [[\.[0-9]+$]] [[]] PATTR_PYENV_SHORT "${PATTR_PYENV}")
  if( ${CMAKE_VERSION} VERSION_LESS 3.12.0 )
    if( "${PATTR_PYENV}" STREQUAL "native" )
      find_package( PythonLibs 3 REQUIRED )
    else()
      execute_process(
        COMMAND python3-config --prefix
        OUTPUT_VARIABLE Python3_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ENCODING AUTO
      )
      execute_process(
        COMMAND python3-config --abiflags
        OUTPUT_VARIABLE Python3_ABIFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ENCODING AUTO
      )
      set( PYTHON_LIBRARY_CANDIDATE "${Python3_PREFIX}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}python${PATTR_PYENV_SHORT}${Python3_ABIFLAGS}${CMAKE_SHARED_LIBRARY_SUFFIX}" )
      if( EXISTS "${PYTHON_LIBRARY_CANDIDATE}" )
        set( PYTHON_LIBRARY "${Python3_PREFIX}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}python${PATTR_PYENV_SHORT}${Python3_ABIFLAGS}${CMAKE_SHARED_LIBRARY_SUFFIX}" )
      else()
        set( PYTHON_LIBRARY "${Python3_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}python${PATTR_PYENV_SHORT}${Python3_ABIFLAGS}${CMAKE_STATIC_LIBRARY_SUFFIX}" )
      endif()
      set( PYTHON_INCLUDE_DIR "${Python3_PREFIX}/include/python${PATTR_PYENV_SHORT}${Python3_ABIFLAGS}" )
      find_package( PythonLibs ${PATTR_PYENV_SHORT} )
    endif()
    set( Python3_INCLUDE_DIRS "${PYTHON_INCLUDE_DIR}" )
    set( Python3_LIBRARIES "${PYTHON_LIBRARY}" )
    set( Python3_FOUND True )
  else()
    if( "${PATTR_PYENV}" STREQUAL "native" )
      find_package( Python3 COMPONENTS Development )
    else()
      find_package( Python3 ${PATTR_PYENV_SHORT} EXACT COMPONENTS Development )
    endif()
  endif()
  try_run(
    GET_SITEDIR_EXECUTED
    GET_SITEDIR_COMPILED
    ${CMAKE_BINARY_DIR}/check
    ${CMAKE_SOURCE_DIR}/check/get_sitedir.cpp
    RUN_OUTPUT_VARIABLE Python3_SITELIB
    COMPILE_OUTPUT_VARIABLE Python3_SITELIB_COMPILER_OUTPUT
    CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${Python3_INCLUDE_DIRS}"
    LINK_LIBRARIES ${Python3_LIBRARIES} ${CMAKE_DL_LIBS} util Threads::Threads
  )
  if( GET_SITEDIR_COMPILED )
    message( "Python Site: ${Python3_SITELIB}" )
  else()
    message( FATAL_ERROR "Unable to detect Python site dir: ${Python3_SITELIB_COMPILER_OUTPUT}" )
  endif()
  try_run(
    GET_USERSITEDIR_EXECUTED
    GET_USERSITEDIR_COMPILED
    ${CMAKE_BINARY_DIR}/check
    ${CMAKE_SOURCE_DIR}/check/get_user_sitedir.cpp
    RUN_OUTPUT_VARIABLE Python3_USERSITELIB
    COMPILE_OUTPUT_VARIABLE Python3_USERSITELIB_COMPILER_OUTPUT
    CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${Python3_INCLUDE_DIRS}"
    LINK_LIBRARIES ${Python3_LIBRARIES} ${CMAKE_DL_LIBS} util Threads::Threads
  )
  if( GET_USERSITEDIR_COMPILED )
    message( "Python User Site: ${Python3_USERSITELIB}" )
  else()
    message( FATAL_ERROR "Unable to detect Python user site dir: ${Python3_USERSITELIB_COMPILER_OUTPUT}" )
  endif()
endif()
