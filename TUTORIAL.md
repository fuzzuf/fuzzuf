# Tutorial

This document covers how to use fuzzuf as a collection of fuzzers in a step-by-step manner. Please refer to other documents if you want to use fuzzuf as a framework for building a new fuzzer. 

## Requirements

* [gcc](https://gcc.gnu.org/) 7 or higher
  * 8 or higher is recommended
  * 10 or higher is required for static analysis
* [CMake](https://cmake.org/) 3.10 or higher
* [Boost C++ library](https://www.boost.org/) 1.53.0 or higher
* [CPython](https://www.python.org/) 3.0 or higher
  * (optional) 3.7 or higher is required to use VUzzer
* [pybind11](https://pybind11.readthedocs.io/en/stable/) 2.2 or higher
* [Nlohmann JSON](https://json.nlohmann.me/) 2.1.1 or higher
* [Crypto\+\+](https://www.cryptopp.com/)
* (optional) [Doxgen](https://www.doxygen.nl/index.html)
* (optional) [Graphviz](https://graphviz.org/)
* (optional) [Mscgen](https://www.mcternan.me.uk/mscgen/)
* (optional) [Dia Diagram Editor](https://sourceforge.net/projects/dia-installer/)
* (optional) [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) [3.7](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz)

### Building fuzzuf

We recommend to use Ubuntu 20.04 (or 18.04) as the operating system to build fuzzuf.

For Ubuntu 20.04, follow the below instruction to build fuzzuf.

```shell
$ sudo apt update
$ sudo apt install -y \
  build-essential cmake git libboost-all-dev \
  python3 nlohmann-json3-dev pybind11-dev libcrypto++-dev
$ git clone https://github.com/fuzzuf/fuzzuf.git
$ cd fuzzuf
$ cmake -B build -DCMAKE_BUILD_TYPE=Release # Change to "Debug" if you want to show debug logs
$ cmake --build build -j$(nproc)
```

On Ubuntu 18.04, execute the following commands instead.  

```shell
$ sudo apt update
$ sudo apt install -y \
  build-essential cmake git libboost-all-dev \
  nlohmann-json-dev pybind11-dev libcrypto++-dev
$ git clone https://github.com/fuzzuf/fuzzuf.git
$ mkdir fuzzuf/build
$ cd $_
$ cmake ../ -DCMAKE_BUILD_TYPE=Release # Need to use a legacy CMake command as apt installs old one
$ make -j$(nproc)
```

### Fuzzing with fuzzuf

This section shows how to run fuzzing with fuzzuf. We use a JPEG Exif parser `exifutil` as a PUT (Program Under Test). The source code is located in [docs/resources/exifutil](/docs/resources/exifutil). To perform fuzzing, we have to instrument programs. To do this, install `afl++-clang` (or `afl-clang`) package for the compiler wrapper.

Hit the following commands to install the compiler wrapper, and build `exifutil` with instrumentations. 

```shell
$ # The following package is only available on Ubuntu 20.04+. 
$ # Install afl-clang instead on older Ubuntu releases.
$ # Both packages install afl-clang-fast.
$ sudo apt install -y afl++-clang
$ pushd docs/resources/exifutil
$ CC=afl-clang-fast make
$ popd
```

Next, we need at least one initial seed for fuzzing. As the program is a JPEG parser, prepare an image such as [docs/resources/exifutil/fuzz_input/jpeg.jpg](/docs/resources/exifutil/fuzz_input/jpeg.jpg). Fuzzers use it as an initial test case for the PUT before applying any kinds of mutations.
Now we can use the `fuzzuf` executable for fuzzing! Hit the following command to start it with AFL fuzzer:

```shell
$ mkdir /tmp/input # Create a directory for an initial seed
$ cp /path/to/jpeg/image.jpg /tmp/input
$ cd /path/to/fuzzuf/build
$ ./fuzzuf afl --in_dir=/tmp/input \
  --out_dir=/tmp/out.afl -- \
  ../docs/resources/exifutil/exifutil -f @@
```

Note that `-f` is an option given to the PUT itself.

If the above command is executed successfully, the following user interface is shown on the terminal, and the fuzzing begins.

![fuzzuf-afl-exifutil](/docs/resources/img/fuzzuf-afl-exifutil.png)

During fuzzing, PUT is executed repeatedly with various mutated inputs. If the execution crashes or hangs, the fuzzer will save the input.
Specifically, suppose the fuzzer found a unique input that crashes the PUT. In that case, it will save the input to the `/tmp/out.afl/crashes` directory and increment the `unique crashes` counter in the upper-right of the UI.
To stop fuzzing, hit `Ctrl-C` to send `SIGINT` to the `fuzzuf` process. Check the inputs triggered crashes and hangs to analyze the root causes.

### Changing Fuzzer

fuzzuf provides various fuzzers other than AFL. Next, we are going to use AFLFast to fuzz the same executable. Please read [AFLFast document](/docs/algorithms/aflfast/algorithm_en.md) to know the characteristics of the AFLFast fuzzer.
To change the fuzzer used, we only have to modify the command line argument (and local options).

```shell
$ ./fuzzuf aflfast --in_dir=/tmp/input \
  --out_dir=/tmp/out.aflfast \
  ../docs/resources/exifutil/exifutil -f @@
```

![fuzzuf-aflfast-exifutil](/docs/resources/img/fuzzuf-aflfast-exifutil.png)

A power scheduling adopted in AFLFast increases fuzzer performance from the original AFL when it is run for a long enough time. For more details, please refer to the document listed above. 

If you want to try other fuzzers, similarly change the command line arguments and options. You may have to apply different processes to the PUT, depending on the fuzzer used. Please refer to the [document directory](/docs/algorithms) to know how to use fuzzers.

