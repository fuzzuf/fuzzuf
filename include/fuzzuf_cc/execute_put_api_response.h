// FIXME: fuzzuf-cc
// をビルド＆インストールするとこのヘッダファイルがfuzzufで認識されるようにしたい
#include "fuzzuf_cc/execute_put_error.h"

namespace fuzzuf::channel {

// FIXME: 一時的な定義。Protocol buffer使って
typedef struct {
  ExecutePUTError error;
  int32_t exit_code;
  int32_t signal_number;
} ExecutePUTAPIResponse;

}  // namespace fuzzuf::channel
