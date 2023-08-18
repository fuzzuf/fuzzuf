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

find_program( NPM_EXECUTABLE NAMES npm )
if( NPM_EXECUTABLE )
  execute_process(
    COMMAND ${NPM_EXECUTABLE} -v
    OUTPUT_VARIABLE NPM_VERSION
    ERROR_VARIABLE NPM_VERSION_ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE NPM_VERSION_RESULT
  )
  message( "${NPM_VERSION}" )
endif()
find_package_handle_standard_args(
  NPM
  REQUIRED_VARS NPM_EXECUTABLE
  VERSION_VAR NPM_VERSION
)

