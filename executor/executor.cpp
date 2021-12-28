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
#include <cstddef>
#include <cassert>
#include <memory>
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"

Executor::Executor(  
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    const std::string path_str_to_write_input
) :
    argv( argv ), 
    exec_timelimit_ms( exec_timelimit_ms ), 
    exec_memlimit( exec_memlimit ), 
    // path_str_to_write_input.c_str()をcargvが参照するが、
    // fs::path::c_strはlifetimeが不定な可能性があり避ける    
    path_str_to_write_input( path_str_to_write_input ),
    child_pid( 0 ),
    input_fd( -1 ),
    null_fd( -1 ),    
    stdin_mode( false )
{    
}

// 前提：
//  - パス path_str_to_write_input にファイルを作れる状態であること
// 責務：
//  - input_fdメンバーを有効化する。つまり、path_str_to_write_inputで指定されたファイルを開き、ファイルディスクリプタを input_fd に代入する。
//  - null_fdメンバーを有効化する。つまり、"/dev/null"ファイルを開き、ファイルディスクリプタを null_fd に代入する。
void Executor::OpenExecutorDependantFiles() {
    input_fd = Util::OpenFile(path_str_to_write_input, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    null_fd = Util::OpenFile("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(input_fd > -1 && null_fd > -1);
}

// 前提：
//  - input_fd がファズのファイルを指したファイルディスクリプタであること
// 責務：
//  - buf が指すデータを input_fd が指すファイルに書き出すこと
//  - 書き出されたファイルは、buf が指すデータだけを含むこと
//  - 書き出されたファイルのサイズは len で指定された値以内であること
//  - ファジング対象のプロセスがこのファイルを読み出すために、file position indicator をファイルの先頭にシークすること
/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */
void Executor::WriteTestInputToFile(const u8 *buf, u32 len) {
    assert(input_fd > -1);

    Util::SeekFile(input_fd, 0, SEEK_SET);
    Util::WriteFile(input_fd, buf, len);
    if (Util::TruncateFile(input_fd, len)) ERROR("ftruncate() failed");
    Util::SeekFile(input_fd, 0, SEEK_SET);
}

// 責務：
//  - child_pid が有効な値であるとき、
//      - child_pid が指すプロセスをkillする。
//      - また、child_pid の値を無効化する（誤動作防止）
// waitpidしないことに注意（別の場所でする前提となっている）
void Executor::KillChildWithoutWait() {
    if (child_pid > 0) {
        kill(child_pid, SIGKILL);
        child_pid = -1;
    }
}
