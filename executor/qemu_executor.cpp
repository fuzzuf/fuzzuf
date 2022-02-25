/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#include "fuzzuf/executor/qemu_executor.hpp"

/**
 * Precondition:
 *    - A file can be created at path path_str_to_write_input.
 */
QEMUExecutor::QEMUExecutor(
    const fs::path &proxy_path,
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    bool forksrv,
    const fs::path &path_to_write_input,
    bool record_stdout_and_err
) : ProxyExecutor ( proxy_path, std::vector<std::string>(), argv, exec_timelimit_ms, exec_memlimit, forksrv,
                    path_to_write_input, QEMUExecutor::QEMU_SHM_SIZE, 0, record_stdout_and_err )
{
    ProxyExecutor::SetCArgvAndDecideInputMode();
    ProxyExecutor::Initilize();
}
