# Binary-only fuzzing with Frida mode

fuzzuf can perform a bianry-only fuzzing by utilizing [AFL\+\+'s Frida mode](https://github.com/AFLplusplus/AFLplusplus/tree/stable/frida_mode).  
It can be used for fuzzing a binary built without a compile-time instrumentation. Make sure the executable is dynamically linked as it needs to inject the library with `LD_PRELOAD`.

Currently, there are limitations on using Frida mode on fuzzuf:
- Only available on x86-64 Linux through CLI.
- [Scripting](https://github.com/AFLplusplus/AFLplusplus/blob/stable/frida_mode/Scripting.md) is not available

## Build instruction and example

To use Frida mode, first, you have to clone AFL++ by yourself, and build `afl-frida-trace.so` by yourself.  
Then, specify AFL++'s path to `-DAFL_ROOT` while generating a CMake's build system.  

Use `--frida` flag to enable/disable a frida mode (disabled by default).

```console
$ git clone https://github.com/AFLplusplus/AFLplusplus.git
$ make -C AFLplusplus/frida_mode
$ cd /path/to/fuzzuf
$ cmake -B build -DAFL_ROOT=/path/to/AFLplusplus # specify other options as required
$ cmake --build build -j`nproc`
$ # Build plain (dynamically linked, uninstrumented) `exifutil` executable
$ make -C docs/resources/exifutil clean all
$ cd build
$ # Currently, frida mode is available for afl and aflfast
$ ./fuzzuf [afl|aflfast] -i ../docs/resources/exifutil/fuzz_input --frida=1 -- \
  ../docs/resources/exifutil/exifutil -f @@
```

You will see that the executable without instrumentation can be fuzzed.

