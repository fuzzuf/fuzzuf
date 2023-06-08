FROM ubuntu:20.04
LABEL org.opencontainers.image.authors="Ricerca Security <fuzzuf-dev@ricsec.co.jp>"

ARG SRC_DIR="/src"
ARG PIN_NAME="pin-3.7-97619-g0d0c92f4f-gcc-linux"
ARG PIN_URL="https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_NAME}.tar.gz"
ARG PIN_PATH="${SRC_DIR}/${PIN_NAME}.tar.gz"
ARG NODE_VERSION="18"

# Install dependencies
RUN apt-get update \
  && apt-get -yq upgrade \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq curl \
  && curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
  && apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    build-essential \
    cmake \
    git \
    libboost-all-dev \
    python3 \
    python3-pip \
    nlohmann-json3-dev \
    pybind11-dev \
    libcrypto++-dev \
    doxygen \
    graphviz \
    mscgen \
    dia \
    wget \
    nodejs \
    afl++-clang \
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
