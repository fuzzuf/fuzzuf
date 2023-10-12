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
if( NOT Python2_FOUND )
  find_program( Python2_CONFIG_EXECUTABLE NAMES python2.7-config )
  if( Python2_CONFIG_EXECUTABLE )
    execute_process(
      COMMAND python2.7-config --prefix
      OUTPUT_VARIABLE Python2_PREFIX
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ENCODING AUTO
    )
    find_program( Python2_INTERPRETOR NAMES python2.7 NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
    if( Python2_INTERPRETOR )
    else()
      find_program( Python2_INTERPRETOR NAMES python2 NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
      if( Python2_INTERPRETOR )
      else()
        find_program( Python2_INTERPRETOR NAMES python NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
      endif()
    endif()
  else()
    find_program( Python2_CONFIG_EXECUTABLE NAMES python2-config )
    if( Python2_CONFIG_EXECUTABLE )
      execute_process(
        COMMAND python2-config --prefix
        OUTPUT_VARIABLE Python2_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ENCODING AUTO
      )
      find_program( Python2_INTERPRETOR NAMES python2 NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
      if( Python2_INTERPRETOR )
      else()
        find_program( Python2_INTERPRETOR NAMES python NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
      endif()
    else()
      find_program( PYTHON_CONFIG_EXECUTABLE NAMES python-config )
      if( PYTHON_CONFIG_EXECUTABLE )
        execute_process(
          COMMAND python-config --prefix
          OUTPUT_VARIABLE Python2_PREFIX
          OUTPUT_STRIP_TRAILING_WHITESPACE
          ENCODING AUTO
        )
        find_program( Python2_INTERPRETOR NAMES python2 NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
        if( Python2_INTERPRETOR )
        else()
          find_program( Python2_INTERPRETOR NAMES python NO_DEFAULT_PATH PATHS ${Python2_PREFIX}/bin )
        endif()
      endif()
    endif()
  endif()
  execute_process(
    COMMAND ${Python2_INTERPRETOR} --version
    ERROR_VARIABLE Python2_VERSION_STR
    ERROR_STRIP_TRAILING_WHITESPACE
    ENCODING AUTO
  )
  string( REGEX REPLACE "Python " "" Python2_VERSION "${Python2_VERSION_STR}" )
  if( "${Python2_VERSION}" VERSION_GREATER_EQUAL "3.0" )
    unset( ${Python2_INTERPRETOR} )
  endif()
endif()
find_package_handle_standard_args(
  Python2
  REQUIRED_VARS Python2_INTERPRETOR
  VERSION_VAR Python2_VERSION
)

