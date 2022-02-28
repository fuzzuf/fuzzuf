# Binary-only fuzzing with Frida mode

fuzzuf can perform a bianry-only fuzzing by utilizing [AFL\+\+'s Frida mode](https://github.com/AFLplusplus/AFLplusplus/tree/stable/frida_mode).  
It can be used for fuzzing a binary built without a compile-time instrumentation. Make sure the executable is dynamically linked as it needs to inject the library with `LD_PRELOAD`.

Currently, there are limitations on using Frida mode on fuzzuf:
- Only available on x86-64 Linux through CLI.
- [Scripting](https://github.com/AFLplusplus/AFLplusplus/blob/stable/frida_mode/Scripting.md) is not available


## Build instruction

To use Frida mode, specify `-DENABLE_FRIDA_TRACE=1` while generating a CMake's build system.  
It will clone `AFLplusplus` submodule and build `afl-frida-trace.so` located under `AFLplusplus/frida_mode/` directory.

```console
$ cd /path/to/fuzzuf
$ # Build plain (dynamically linked, uninstrumented) `exifutil` executable
$ make -C docs/resources/exifutil clean all
$ cmake -B build ... -DENABLE_FRIDA_TRACE=1
$ cmake --build build -j`nproc`
$ cd build
$ # Currently, frida mode is available for afl and aflfast
$ ./fuzzuf [afl|aflfast] -i ../docs/resources/exifutil/fuzz_input --frida=1 -- \
  ../docs/resources/exifutil/exifutil -f @@
```

You will see that the executable without instrumentation can be fuzzed.

