FROM ubuntu:20.04
LABEL org.opencontainers.image.authors="Ricerca Security <fuzzuf-dev@ricsec.co.jp>"

ARG PIN_NAME="pin-3.7-97619-g0d0c92f4f-gcc-linux"
ARG PIN_URL="https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_NAME}.tar.gz"
ARG PIN_PATH="/src/${PIN_NAME}.tar.gz"
ARG NODE_VERSION="17"

# Install dependencies
RUN apt-get update \
  && apt-get -yq upgrade \
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
    curl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install fuzzuf/polytracker
RUN python3 -m pip install pytest \
  && mkdir -p /src \
  && git clone https://github.com/fuzzuf/polytracker.git /src/polytracker \
  && cd /src/polytracker \
  && python3 -m pip install -e .

# Download and extract Intel Pin
RUN mkdir -p /src \
  && cd /src \
  && wget ${PIN_URL} -O ${PIN_PATH} \
  && tar -xf ${PIN_PATH}

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
  && apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq nodejs \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
