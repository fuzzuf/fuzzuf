#
# fuzzuf
# Copyright (C) 2023 Ricerca Security
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

find_program( RAGEL_EXECUTABLE NAMES ragel )
if( RAGEL_EXECUTABLE )
  execute_process(
    COMMAND ${CMAKE_SOURCE_DIR}/check/ragel_version.sh ${RAGEL_EXECUTABLE}
    OUTPUT_VARIABLE RAGEL_VERSION
    ERROR_VARIABLE RAGEL_VERSION_ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE RAGEL_VERSION_RESULT
  )
  message( "${RAGEL_VERSION}" )
endif()
find_package_handle_standard_args(
  RAGEL
  REQUIRED_VARS RAGEL_EXECUTABLE
  VERSION_VAR RAGEL_VERSION
)

