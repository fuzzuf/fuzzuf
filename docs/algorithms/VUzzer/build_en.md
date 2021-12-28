# Building VUzzer

VUzzer has the following additional requirements:

* Python 3.7 or higher
* Intel Pin 3.7
* fuzzuf/PolyTracker

This document covers the above dependency installations and how to build VUzzer.

## Install Python

PolyTracker requires Python version 3.7 or above.

On Ubuntu 20.04, the default `python3` (version 3.8) apt package meets this requirement. You can skip this section and go to the Intel Pin section.

If you use Ubuntu 18.04 or other environments, you must install Python 3.7+ manually or with a Python version manager such as [pyenv](https://github.com/pyenv/pyenv).

The below example shows Python installation using pyenv.

```bash
### Install dependencies required by Python. Refer to the following document.
### https://github.com/pyenv/pyenv/wiki#suggested-build-environment

### Download pyenv and add it to PATH
curl https://pyenv.run | bash
export PATH="$HOME/.pyenv/bin:$PATH"
eval $(pyenv init --path)

### Install Python 3.7 in pyenv environment.
pyenv install 3.7.12
pyenv local 3.7.12
```

If you use other methods, ensure that the `python3` command meets the requirement.

Check if `python3` version is 3.7 or higher as follows.

```bash
$ python3 --version
Python 3.7.12
```

Go to the following Intel Pin section.

## Download Intel Pin

Download Intel Pin 3.7 from the Intel official website, and extract the tarball.

```bash
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
tar -zxvf pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
```

Go to the next PolyTracker section.

## Install PolyTracker

VUzzer implementation on fuzzuf employs [fuzzuf/polytracker](https://github.com/fuzzuf/polytracker) for data flow analysis.

<details>
<summary>Why PolyTracker?</summary>

The reason why we use PolyTracker instead of [libdft64](https://github.com/vusec/vuzzer64/tree/master/libdft64), used by the [VUzzer reference implementation](https://github.com/vusec/vuzzer64) is that we conclude that libdft64 cannot achieve enough analysis accuracy to reproduce the original VUzzer performance on a newer version of Ubuntu (18.04/20.04).

Our [trailofbits/polytracker](https://github.com/trailofbits/polytracker) fork adds some changes to reproduce libdft64 data flow analysis.
</details>

Refer to the [PolyTracker README](https://github.com/fuzzuf/polytracker/blob/feature/make-polytracker-libdft64-compatible/README.md) for PolyTracker installation.

## Build fuzzuf

Run the following command in the fuzzuf local repository specifying `PIN_ROOT` to the extracted Intel Pin 3.7 directory.

```bash
cd /path/to/fuzzuf/directory
### Run in the fuzzuf root directory.
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DDEFAULT_RUNLEVEL=Debug -DPIN_ROOT=/path/to/extracted/pin/dir
cd build
make
```
