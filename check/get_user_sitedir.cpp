/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
#include <Python.h>

#include <iostream>
#include <string>
int main() {
  Py_Initialize();
  auto site = PyImport_ImportModule("site");
  if (!site) return 1;
  auto path = PyObject_GetAttrString(site, "USER_SITE");
  if (!path) return 1;
  auto encoded_path = PyUnicode_EncodeLocale(path, nullptr);
  if (!encoded_path) return 1;
  std::cout << PyBytes_AS_STRING(encoded_path) << std::flush;
  Py_Finalize();
}
