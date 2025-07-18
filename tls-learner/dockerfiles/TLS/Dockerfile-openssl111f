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

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

RUN chmod 777 /tmp

# Use ubuntu as default username
USER ubuntu
WORKDIR /home/ubuntu

# Set up environment variables
ENV WORKDIR="/home/ubuntu/experiments"
RUN mkdir -p $WORKDIR

# Copy the key folder from the Dockerfile directory to the container
COPY --chown=ubuntu:ubuntu key ${WORKDIR}/key

# Download and compile OpenSSL for fuzzing
RUN cd ${WORKDIR} && \
    git clone https://gitee.com/zhangph12138/openssl.git && \
    cd openssl && \
    cp -r ${WORKDIR}/key ./ && \
    git checkout 0437435a && \
    CC=clang ./config no-shared --with-rand-seed=none && \
    CC=clang make include/openssl/configuration.h include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
    CC=clang make apps/openssl

# Set the working directory
WORKDIR ${WORKDIR}

# Create a script to run openssl s_server
RUN echo '#!/bin/bash' > /home/ubuntu/start_server.sh && \
    echo 'openssl s_server -cert ${WORKDIR}/key/server.cer -key ${WORKDIR}/key/deserver.key -CAfile ${WORKDIR}/key/ca.cer -HTTP' >> /home/ubuntu/start_server.sh && \
    chmod +x /home/ubuntu/start_server.sh

# Set the script to run on container start
CMD ["/home/ubuntu/start_server.sh"]
