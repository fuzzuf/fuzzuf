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
find_package( Python3x )
if(NOT Pybind11_ROOT)
  string(REPLACE ";" "/pybind11/include;" Pybind11_SITES "${Python3_SITELIB}")
  find_path( Pybind11_INCLUDE_DIRS pybind11/pybind11.h PATHS ${Pybind11_SITES} ${Python3_USERSITELIB}/pybind11/include )
else()
  find_path( Pybind11_INCLUDE_DIRS pybind11/pybind11.h NO_DEFAULT_PATH PATHS ${Pybind11_ROOT}/include )
endif()
try_run(
  GET_PYBIND11_VERSION_EXECUTED
  GET_PYBIND11_VERSION_COMPILED
  ${CMAKE_BINARY_DIR}/check
  ${CMAKE_SOURCE_DIR}/check/get_pybind11_version.cpp
  RUN_OUTPUT_VARIABLE Pybind11_VERSION
  CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${Pybind11_INCLUDE_DIRS};${Python3_INCLUDE_DIRS}"
  LINK_LIBRARIES ${Python3_LIBRARIES}
)
if( GET_PYBIND11_VERSION_EXECUTED AND Pybind11_INCLUDE_DIRS )
  set( Pybind11_FOUND TRUE )
else()
  set( Pybind11_FOUND FALSE )
  set( Pybind11_INCLUDE_DIR )
endif()
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
  Pybind11
  VERSION_VAR Pybind11_VERSION
  REQUIRED_VARS Pybind11_INCLUDE_DIRS
)
