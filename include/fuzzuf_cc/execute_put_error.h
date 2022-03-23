// FIXME: fuzzuf-cc をビルド＆インストールするとこのヘッダファイルがfuzzufで認識されるようにしたい

// FIXME: 一時的な定義。Protocol buffer使って
enum ExecutePUTError {
    None = 0,
    DaemonAlreadyExit,
    DaemonBusyError,
    SpawnPUTError,
};
