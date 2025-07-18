FROM ubuntu:20.04

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
    apt-get -y install sudo \ 
    apt-utils \
    build-essential \
    openssl \
    clang \
    git \
    autoconf \
    libgnutls28-dev \
    libssl-dev \
    llvm \
    python3-pip \
    wget

RUN chmod 777 /tmp

# Set up environment variables
ENV WORKDIR="/home/ubuntu/experiments"
RUN mkdir -p ${WORKDIR} && \
    mkdir -p /home/ubuntu

# Copy the key folder
COPY ../key ${WORKDIR}/key
COPY rand.patch ${WORKDIR}/rand.patch

# Build OpenSSL
RUN cd ${WORKDIR} && \
    git clone https://gitee.com/zhangph12138/openssl.git && \
    cd openssl && \
    cp -r ${WORKDIR}/key ./ && \
    git checkout OpenSSL_1_1_1f && \
    patch -p1 < ${WORKDIR}/rand.patch && \
    ./config no-shared --with-rand-seed=none && \
    make $MAKE_OPT

# Install TLS Fuzzer
RUN cd ${WORKDIR} && \
    git clone https://gitee.com/zhangph12138/tlsfucker.git && \
    cd tlsfucker && \
    python3 -m pip install --upgrade pip && \
    pip config set global.index-url https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple && \
    pip install -r ./requirements.txt

# Set working directory
WORKDIR ${WORKDIR}

# # Create startup script
# RUN echo '#!/bin/bash\nopenssl s_server -cert ${WORKDIR}/key/server.cer -key ${WORKDIR}/key/deserver.key -CAfile ${WORKDIR}/key/ca.cer -HTTP' > /start_server.sh && \
#     chmod +x /start_server.sh

# # Start service
# CMD ["/start_server.sh"]