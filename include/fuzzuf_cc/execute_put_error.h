// FIXME: fuzzuf-cc をビルド＆インストールするとこのヘッダファイルがfuzzufで認識されるようにしたい

// FIXME: 一時的な定義。Protocol buffer使って
typedef enum {
    None = 0,
    DaemonAlreadyExitError,
    DaemonBusyError,
    SpawnPUTError,
    UnknownPUTStateError,
    NoResponseError,
} ExecutePUTError;