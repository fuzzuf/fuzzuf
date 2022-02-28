### PUTをソースディレクトリからビルドディレクトリへコピーする。
### PUTについての詳細はこのディレクトリのREADME.md参照

file(
    COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/libjpeg/
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/libjpeg/
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/zeroone
    ${CMAKE_CURRENT_BINARY_DIR}/zeroone
    COPYONLY
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/command_wrapper
    ${CMAKE_CURRENT_BINARY_DIR}/command_wrapper
    COPYONLY
)

file(
    COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/calc/
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/calc/
)

file(
    COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/quickjs/
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/quickjs/
)

file(
    COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/nautilus/
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/nautilus/
)
