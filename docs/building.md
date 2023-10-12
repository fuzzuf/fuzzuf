# Building

## Building with a Development Container

We provide a container image to set up a development environment for fuzzuf quickly.
Install Docker and run:

```bash
./scripts/dev_cli.sh build
```

This command will download the container image and build all the features and documentation in the container.

`build` can specify debug/release build and runlevel with flags. The default is `--debug` and `--runlevel Debug`.
To build with release without debug output:

```bash
./scripts/dev_cli.sh build --release --runlevel Release
```

To run unit tests:

```bash
./scripts/dev_cli.sh tests
```

To run an interactive shell inside a container:

```bash
./scripts/dev_cli.sh shell
```

See `help` for detailed usage:

```bash
./scripts/dev_cli.sh help
```

## Building Manually

### Recommended Environment

* Ubuntu 22.04
* Ubuntu 20.04

### Dependencies

#### Minimum Dependencies

The following dependencies must be met to build fuzzuf.

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

#### Dependencies for Instrumentation

The following dependencies are required for the instrumentation of the PUT.

* [AFL\+\+ Clang](https://github.com/AFLplusplus/AFLplusplus)

#### Dependencies for Generating Documentation

The following additional dependencies are required to generate documentation using Doxygen.

* [Doxgen](https://www.doxygen.nl/index.html)
* [Graphviz](https://graphviz.org/)
* [Mscgen](https://www.mcternan.me.uk/mscgen/)
* [Dia Diagram Editor](https://sourceforge.net/projects/dia-installer/)

#### Dependencies for VUzzer

The following additional dependencies are required to use VUzzer.

* [CPython](https://www.python.org/) 3.7 or higher
* [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) [3.7](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz)
* [fuzzuf/polytracker](https://github.com/fuzzuf/polytracker)

#### Dependencies for DIE

The following additional dependencies are required to use DIE.

* [Node.js](https://nodejs.org/en/download/) (Tested on 16.13 LTS at Jan 17th, 2022)
  * npm (6 or later is recommended)
  * node (10 or later is recommended)
* Python 3 (3.6 or later is recommended)

### Manual Build

#### On Ubuntu 20.04

To build a minimal fuzzuf on Ubuntu 20.04, install the dependencies as follows:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  git \
  libboost-all-dev \
  python3 \
  nlohmann-json3-dev \
  pybind11-dev \
  libcrypto++-dev
```

Next, clone the repository and build fuzzuf:

```bash
git clone https://github.com/fuzzuf/fuzzuf.git
cd fuzzuf
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

#### On Ubuntu 18.04

To build a minimal fuzzuf on Ubuntu 18.04, install the dependencies as follows:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  git \
  libboost-all-dev \
  python3 \
  nlohmann-json-dev \
  pybind11-dev \
  libcrypto++-dev
```

Next, clone the repository and build fuzzuf:

```bash
git clone https://github.com/fuzzuf/fuzzuf.git
mkdir -p fuzzuf/build
cd $_
cmake ../ -DCMAKE_BUILD_TYPE=Debug # Need to use a legacy CMake command as apt installs old one
make -j$(nproc)
```

### Manual Build of VUzzer

Refer to the [build instruction](/docs/algorithms/vuzzer/build_en.md) for manual build of VUzzer.

### Manual Build of DIE

Refer to the [build instruction](/docs/algorithms/die/algorithm_en.md) for build build of DIE.

### Run Unit Tests

Build the `test` target to run unit tests:

```bash
cmake --build build --target test
```

Note that this command will run all tests by default, so some tests fail if dependencies are not met.

### Generate Documentation

To generate documentation with Doxygen, build the `fuzzuf_doc` target with the dependencies satisfied. On Ubuntu 20.04, install the dependencies as follows:

```bash
sudo apt update
sudo apt install -y \
  doxygen \
  graphviz \
  mscgen \
  dia
```

Build `fuzzuf_doc` target after setting `ENABLE_DOXYGEN=1` as follows:

```bash
cmake -B build -DENABLE_DOXYGEN=1
cmake --build build --target fuzzuf_doc
```

## Note on Building on newer CPUs

Ubuntu 20.04 uses an older version of the compiler (gcc 9) by default. Therefore, as reported in [issue #21](https://github.com/fuzzuf/fuzzuf/issues/21), release builds on newer CPUs such as TigerLake may fail due to lack of native support for the architecture. This problem is a possible issue for both containerized build and manual build. You need to install a new compiler and specify it at build time as a workaround.

For example, if you installed gcc 10, run:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -D CMAKE_C_COMPILER=gcc-10 -D CMAKE_CXX_COMPILER=g++-10
```

## Learn More

[tutorial.md](/docs/tutorial.md) describes how to instrument PUTs and fuzz with AFL and AFLFast using a program with intentional bugs.
For more information about each algorithm, please refer to the documentation in [docs/algorithms](/docs/algorithms).
