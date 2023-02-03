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
if(DEFINED AFL_ROOT)
  find_program( QEMU_EXECUTABLE afl-qemu-trace HINTS ${AFL_ROOT}/ )
else()
  message( STATUS "QEMU AFL location (AFL_ROOT) is not specified." )
endif()

find_package_handle_standard_args( QEMU REQUIRED_VARS QEMU_EXECUTABLE )
