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
#pragma once

#include "fuzzuf/executor/proxy_executor.hpp"

// A class for fuzz executions with Intel PT
class PTExecutor : public ProxyExecutor {
public:
    static constexpr const char* PATH_SHM_ENV_VAR = "__AFL_SHM_ID"; // TODO: Use different environment variable.
    static constexpr const char* FAV_SHM_ENV_VAR = "__AFL_PTFAV_SHM_ID";

    // shm_size is fixed in PTrix pt-proxy-fast.
    static constexpr u32 PATH_SHM_SIZE = (1U << 16);
    static constexpr u32 FAV_SHM_SIZE = (1U << 16);

    const u32 path_shm_size;
    const u32 fav_shm_size;

    int path_shmid;
    int fav_shmid;

    u8 *path_trace_bits;
    u8 *fav_trace_bits;

    PTExecutor(
        const fs::path &proxy_path,
        const std::vector<std::string> &argv,
        u32 exec_timelimit_ms,
        u64 exec_memlimit,
        bool forksrv,
        const fs::path &path_to_write_input,
        int cpuid_to_bind,
        // FIXME: see the comment for the same variable in NativeLinuxExecutor
        bool record_stdout_and_err = false
    );

    InplaceMemoryFeedback GetAFLFeedback() = delete;
    InplaceMemoryFeedback GetBBFeedback() = delete;
    InplaceMemoryFeedback GetPathFeedback();
    InplaceMemoryFeedback GetFavFeedback();

    void SetupSharedMemories() override;
    void ResetSharedMemories() override;
    void EraseSharedMemories() override;
    void SetupEnvironmentVariablesForTarget() override;
};
