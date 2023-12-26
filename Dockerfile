FROM ubuntu:22.04
LABEL org.opencontainers.image.authors="Ricerca Security <fuzzuf-dev@ricsec.co.jp>"

ARG SRC_DIR="/src"
ARG PIN_NAME="pin-3.7-97619-g0d0c92f4f-gcc-linux"
ARG PIN_URL="https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_NAME}.tar.gz"
ARG PIN_PATH="${SRC_DIR}/${PIN_NAME}.tar.gz"
ARG NODE_VERSION="18"
ARG LLVM_VERSION="15"

ENV BUILD_TYPE "Debug"
ENV RUNLEVEL "Debug"
ENV PIN_ROOT ${SRC_DIR}/${PIN_NAME}
ENV DOXYGEN "0"
ENV ALGORITHMS "all"

# Install dependencies
RUN apt-get update \
  && apt-get -yq upgrade \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq ca-certificates curl gnupg lsb-release \
  && export CODENAME=$(lsb_release -cs) \
  && mkdir -p /etc/apt/keyrings \
  && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
  && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_VERSION}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
  && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /etc/apt/keyrings/llvmsource.gpg \
  && echo "deb [signed-by=/etc/apt/keyrings/llvmsource.gpg] http://apt.llvm.org/${CODENAME}/ llvm-toolchain-${CODENAME}-${LLVM_VERSION} main" | tee /etc/apt/sources.list.d/llvmsource.list \
  && apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    afl++-clang \
    build-essential \
    clang-15 \
    cmake \
    dia \
    doxygen \
    git \
    graphviz \
    libboost-all-dev \
    libcrypto++-dev \
    libfdt-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    lld-15 \
    llvm-15 \
    mscgen \
    nlohmann-json3-dev \
    nodejs \
    python2.7-dev \
    python3 \
    python3-pip \
    pybind11-dev \
    ragel \
    wget \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install fuzzuf/polytracker
RUN mkdir -p ${SRC_DIR} \
  && git clone https://github.com/fuzzuf/polytracker.git ${SRC_DIR}/polytracker \
  && cd ${SRC_DIR}/polytracker \
  && python3 -m pip install pytest \
  && python3 -m pip install -e .

# Download and extract Intel Pin
RUN mkdir -p ${SRC_DIR} \
  && cd ${SRC_DIR} \
  && wget ${PIN_URL} -O ${PIN_PATH} \
  && tar -xf ${PIN_PATH}

# Install fuzzuf/fuzzuf-cc
RUN mkdir -p ${SRC_DIR} \
  && git clone https://github.com/fuzzuf/fuzzuf-cc.git ${SRC_DIR}/fuzzuf-cc \
  && cd ${SRC_DIR}/fuzzuf-cc \
  && cmake -B build -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  && cmake --build build -j$(nproc) \
  && cd ${SRC_DIR}/fuzzuf-cc/build \
  && make install
