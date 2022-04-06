#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <optional>

#include "fuzzuf_cc/execute_put_api_response.h"

class FdChannel /* : public Channel */ {
public:
    FdChannel();
    ~FdChannel();

    // PUT API
    void SetPUTExecutionTimeout(uint64_t timeout_us);
    void ReadStdin();
    void SaveStdoutStderr();
    ExecutePUTAPIResponse ExecutePUT();
    void SetupForkServer(char *const pargv[]);
    void TerminateForkServer();

private:
    ssize_t Send(void *buf, size_t size, const char* comment = "");
    ssize_t Recv(void *buf, size_t size, const char* comment = "");

    void AttachToServer(uint64_t executor_id);
    std::optional<pid_t> WaitForkServerStart();
    std::optional<pid_t> DoHandShake(uint64_t executor_id);

    // TODO: fuzzuf-cc がPUTに付加した情報をもとに設定したいな
    // afl-gcc を使い回す都合で、本家とバッチングしない値を使う
    static const int FORKSRV_FD_READ = 196; // 本家とバッチングしない値で
    static const int FORKSRV_FD_WRITE = 197;

    pid_t forksrv_pid;
    int forksrv_read_fd;
    int forksrv_write_fd;
};
