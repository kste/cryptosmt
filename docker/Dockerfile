FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# Install all packages including solvers available in repo
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    wget \
    curl \
    zlib1g-dev \
    libm4ri-dev \
    python3 \
    python3-dev \
    python3-pip \
    python3-yaml \
    python3-pytest \
    python3-pytest-mock \
    python3-tqdm \
    python3-rich \
    libboost-all-dev \
    bison \
    flex \
    libsqlite3-dev \
    libgmp-dev \
    libmpfr-dev \
    perl \
    g++ \
    pkg-config \
    cryptominisat \
    boolector \
    meson \
    ninja-build \
    unzip

WORKDIR /home/tools/

# Build MiniSat (required for STP)
RUN git clone https://github.com/stp/minisat && \
    cd minisat && \
    mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install

# Build STP (Latest version from source as requested)
RUN git clone https://github.com/stp/stp && \
    cd stp && \
    git submodule update --init --recursive && \
    mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && \
    cp lib/libabc-pic.so /usr/local/lib/ && \
    ldconfig

# Build Bitwuzla
RUN git clone https://github.com/bitwuzla/bitwuzla && \
    cd bitwuzla && \
    git submodule update --init --recursive && \
    ./configure.py && \
    cd build && \
    ninja install

# Download and install ApproxMC binary
RUN wget https://github.com/meelgroup/approxmc/releases/latest/download/approxmc-linux-amd64.zip && \
    unzip approxmc-linux-amd64.zip && \
    chmod +x approxmc && \
    mv approxmc /usr/local/bin/

RUN ldconfig

# Copy local code
WORKDIR /home/tools/cryptosmt
COPY . .

# Update config.py to use system paths
RUN sed -i 's|PATH_STP = .*|PATH_STP = "/usr/local/bin/stp"|' config.py && \
    sed -i 's|PATH_CRYPTOMINISAT = .*|PATH_CRYPTOMINISAT = "/usr/bin/cryptominisat5"|' config.py && \
    sed -i 's|PATH_BOOLECTOR = .*|PATH_BOOLECTOR = "/usr/bin/boolector"|' config.py && \
    sed -i 's|PATH_BITWUZLA = .*|PATH_BITWUZLA = "/usr/local/bin/bitwuzla"|' config.py && \
    sed -i 's|PATH_APPROXMC = .*|PATH_APPROXMC = "/usr/local/bin/approxmc"|' config.py

ENTRYPOINT ["python3", "cryptosmt.py"]
