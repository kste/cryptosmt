FROM debian:latest

# Install all packages
RUN apt-get update && apt-get install -y git build-essential cmake wget curl

WORKDIR /home/tools/
RUN git clone https://github.com/agurfinkel/minisat && \
    git clone https://github.com/msoos/cryptominisat && \
    git clone https://github.com/stp/stp && \
    git clone https://github.com/Boolector/boolector && \
    git clone https://github.com/kste/cryptosmt

WORKDIR /home/tools/minisat
RUN apt-get install -y zlib1g-dev
RUN make && make install

WORKDIR /home/tools/cryptominisat
RUN apt-get install -y libm4ri-dev python3 python3-dev libboost-all-dev
RUN mkdir build
WORKDIR build
RUN cmake ../ && make && make install

WORKDIR /home/tools/stp/
RUN apt-get install -y bison flex
RUN mkdir build
WORKDIR build
RUN cmake ../ && make && make install

WORKDIR /home/tools/boolector
RUN ./contrib/setup-lingeling.sh && ./contrib/setup-btor2tools.sh
RUN ./configure.sh --no-minisat --no-cms && cd build && make && make install

WORKDIR /home/tools/cryptosmt
RUN apt-get install -y python3-pip
RUN pip3 install pyyaml

# Clean
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
