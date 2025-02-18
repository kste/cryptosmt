# Use Debian as the base image
FROM debian:latest

# Install all necessary system dependencies
RUN apt-get update && apt-get install -y \
    git build-essential cmake libgmp-dev \
    zlib1g-dev python3 python3-dev libboost-all-dev \
    bison flex python3-pip help2man \
    perl curl libtinfo-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /home/tools/

# Clone and Build CaDiCaL
WORKDIR /home/tools/cadical
RUN git clone https://github.com/meelgroup/cadical . && \
    git checkout mate-only-libraries-1.8.0 && \
    ./configure && make && \
    cp build/libcadical.* /usr/local/lib/ && \
    mkdir -p /usr/local/include/cadical && \
    cp -r src/* /usr/local/include/cadical/ && \
    ldconfig

# Clone and Build CaDiBack
WORKDIR /home/tools/cadiback
RUN git clone https://github.com/meelgroup/cadiback . && \
    git checkout mate && \
    ./configure && make && \
    cp libcadiback.so /usr/local/lib/ && \
    chmod +x /usr/local/lib/libcadiback.so && \
    ldconfig

# Clone and Build CryptoMiniSat
WORKDIR /home/tools/cryptominisat
RUN git clone https://github.com/msoos/cryptominisat . && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_LIBRARY_PATH=/usr/local/lib \
          -DCMAKE_INCLUDE_PATH=/usr/local/include/cadical .. && \
    make && make install && \
    ldconfig

# Ensure CryptoMiniSat shared libraries are correctly linked
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/cryptominisat.conf && ldconfig

# **Auto-detect CryptoMiniSat version and create symlink for STP**
RUN latest_lib=$(ls /usr/local/lib/libcryptominisat5.so.* | sort -V | tail -n 1) && \
    ln -sf "$latest_lib" /usr/local/lib/libcryptominisat5.so.5.11 && \
    ldconfig

# Clone Other Tools
WORKDIR /home/tools
RUN git clone https://github.com/agurfinkel/minisat && \
    git clone https://github.com/stp/stp && \
    git clone https://github.com/Boolector/boolector && \
    git clone https://github.com/kste/cryptosmt

# Build Minisat
WORKDIR /home/tools/minisat
RUN make && make install && \
    find build -name "libminisat.*" -exec cp {} /usr/local/lib/ \; && \
    ldconfig

# Build STP (Without Rebuilding)
WORKDIR /home/tools/stp
RUN git submodule update --init --recursive && \
    ./scripts/deps/setup-gtest.sh && \
    ./scripts/deps/setup-outputcheck.sh && \
    ./scripts/deps/setup-cms.sh && \
    ./scripts/deps/setup-minisat.sh && \
    mkdir -p build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_LIBRARY_PATH=/usr/local/lib \
        -DCMAKE_INCLUDE_PATH=/usr/local/include/cadical \
        -DCMAKE_CXX_FLAGS="-Wl,-rpath,/usr/local/lib" && \
    make -j$(nproc) && make install && \
    ldconfig

# Ensure STP is in the PATH
RUN ln -s /usr/local/bin/stp /usr/bin/stp || true

# Fix STP Shared Library Issue (CryptoMiniSat Dependency)
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local-libs.conf && \
    ldconfig

# Set LD_LIBRARY_PATH to include /usr/local/lib
ENV LD_LIBRARY_PATH="/usr/local/lib"

# Build Boolector
WORKDIR /home/tools/boolector
RUN ./contrib/setup-lingeling.sh && ./contrib/setup-btor2tools.sh
RUN ./configure.sh && cd build && make && make install

# Build CryptoSMT
WORKDIR /home/tools/cryptosmt
RUN python3 -m pip install --break-system-packages pyyaml

# Ensure All Binaries are in PATH
ENV PATH="/usr/local/bin:/home/tools/stp/build:/home/tools/minisat:$PATH"

# Final Cleanup to Reduce Image Size
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /home/tools/*/.git
