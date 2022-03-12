// FIXME: fuzzuf-cc をビルド＆インストールするとこのヘッダファイルがfuzzufで認識されるようにしたい
#include "fuzzuf_cc/execute_put_error.h"

// FIXME: 一時的な定義。Protocol buffer使って
typedef struct {
    enum ExecutePUTError error;
    int32_t exit_code;
} ExecutePUTAPIResponse;