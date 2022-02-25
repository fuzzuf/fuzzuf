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
#include "fuzzuf/executor/pt_executor.hpp"

#include "fuzzuf/logger/logger.hpp"

// NOTE:
//    - PTExecutor assume it can create a file at `path_to_write_input`.
PTExecutor::PTExecutor(
    const fs::path &proxy_path,
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    bool forksrv,
    const fs::path &path_to_write_input,
    bool record_stdout_and_err
) : ProxyExecutor ( proxy_path, std::vector<std::string>(), argv, exec_timelimit_ms, exec_memlimit, forksrv,
                    path_to_write_input, 0, 0, record_stdout_and_err ),
    path_shm_size ( PTExecutor::PATH_SHM_SIZE ),
    fav_shm_size ( PTExecutor::FAV_SHM_SIZE )
{
    if (path_shm_size > 0 || fav_shm_size > 0) {
        has_shared_memories = true;
    }

    ProxyExecutor::SetCArgvAndDecideInputMode();
    ProxyExecutor::Initilize();
}

void PTExecutor::SetupSharedMemories() {
    if (path_shm_size > 0) {
        path_shmid = shmget(IPC_PRIVATE, path_shm_size, IPC_CREAT | IPC_EXCL | 0600);
        if (path_shmid < 0) ERROR("shmget() failed");

        path_trace_bits = (u8 *)shmat(path_shmid, nullptr, 0);
        if (path_trace_bits == (u8 *)-1) ERROR("shmat() failed");
    }

    if (fav_shm_size > 0) {
        fav_shmid = shmget(IPC_PRIVATE, fav_shm_size, IPC_CREAT | IPC_EXCL | 0600);
        if (fav_shmid < 0) ERROR("shmget() failed");

        fav_trace_bits = (u8 *)shmat(fav_shmid, nullptr, 0);
        if (fav_trace_bits == (u8 *)-1) ERROR("shmat() failed");
    }
}

void PTExecutor::ResetSharedMemories() {
    if (path_shm_size > 0) {
        std::memset(path_trace_bits, 0, path_shm_size);
    }

    if (fav_shm_size > 0) {
        std::memset(fav_trace_bits, 0, fav_shm_size);
    }

    MEM_BARRIER();
}

void PTExecutor::EraseSharedMemories() {
    if (path_shm_size > 0) {
        if (shmdt(path_trace_bits) == -1) ERROR("shmdt() failed");
        path_trace_bits = nullptr;
        if (shmctl(path_shmid, IPC_RMID, 0) == -1) ERROR("shmctl() failed");
        path_shmid = INVALID_SHMID;
    }

    if (fav_shm_size > 0) {
        if (shmdt(fav_trace_bits) == -1) ERROR("shmdt() failed");
        fav_trace_bits = nullptr;
        if (shmctl(fav_shmid, IPC_RMID, 0) == -1) ERROR("shmctl() failed");
        fav_shmid = INVALID_SHMID;
    }
}

void PTExecutor::SetupEnvironmentVariablesForTarget() {
    ProxyExecutor::SetupEnvironmentVariablesForTarget();

    if (path_shm_size > 0) {
        std::string path_shmstr = std::to_string(path_shmid);
        setenv(PATH_SHM_ENV_VAR, path_shmstr.c_str(), 1);
    } else {
        // make sure to unset the environmental variable if it's unused
        unsetenv(PATH_SHM_ENV_VAR);
    }

    if (fav_shm_size > 0) {
        std::string fav_shmstr = std::to_string(fav_shmid);
        setenv(FAV_SHM_ENV_VAR, fav_shmstr.c_str(), 1);
    } else {
        // make sure to unset the environmental variable if it's unused
        unsetenv(FAV_SHM_ENV_VAR);
    }
}

InplaceMemoryFeedback PTExecutor::GetPathFeedback() {
    return InplaceMemoryFeedback(path_trace_bits, path_shm_size, lock);
}

InplaceMemoryFeedback PTExecutor::GetFavFeedback() {
    return InplaceMemoryFeedback(fav_trace_bits, fav_shm_size, lock);
}