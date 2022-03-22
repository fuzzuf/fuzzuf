#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzzuf_cc/execute_put_api_response.h"

class FdChannel /* : public Channel */ {
public:
    FdChannel();
    ~FdChannel();

    // PUT API
    // TODO: これは暫定。フェーズ3で標準入出力の record 機能の実現のために、Execute開始と終了待ちを別々に扱う可能性あり。
    ExecutePUTAPIResponse ExecutePUT();
    void SetupForkServer(char *const pargv[]);
    void TerminateForkServer();

private:
    ssize_t Send(void *buf, size_t size);
    ssize_t Recv(void *buf, size_t size);

    pid_t WaitForkServerStart();

    // TODO: fuzzuf-cc がPUTに付加した情報をもとに設定したいな
    // afl-gcc を使い回す都合で、本家とバッチングしない値を使う
    static const int FORKSRV_FD_READ = 196; // 本家とバッチングしない値で
    static const int FORKSRV_FD_WRITE = 197;

    pid_t forksrv_pid;
    int forksrv_read_fd;
    int forksrv_write_fd;
};