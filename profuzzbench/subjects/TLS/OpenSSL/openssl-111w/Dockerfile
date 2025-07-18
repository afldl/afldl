FROM ubuntu:20.04

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
    apt-get -y install sudo \ 
    apt-utils \
    build-essential \
    openssl \
    clang \
    graphviz-dev \
    git \
    autoconf \
    libgnutls28-dev \
    libssl-dev \
    llvm \
    python3-pip \
    nano \
    net-tools \
    vim \
    gdb \
    netcat \
    strace \
    wget \
    cmake \
    build-essential \
    libgtk2.0-dev \
   libavcodec-dev \
   libavformat-dev \
   libjpeg-dev \
   libswscale-dev \
   libtiff5-dev \
   libgtk2.0-dev \
   pkg-config \
   unzip \
   bash


# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

RUN chmod 777 /tmp

RUN pip3 install gcovr==4.2

# Use root as default username
USER root
WORKDIR /home/ubuntu

# Import environment variable to pass as parameter to make (e.g., to make parallel builds with -j)
ARG MAKE_OPT


# install opencv- 3.4.7
# RUN wget https://github.com/opencv/opencv/archive/3.4.7.zip && \
RUN wget http://ssh84jzt0.hd-bkt.clouddn.com/opencv-3.4.7.zip && \
    unzip opencv-3.4.7.zip && cd opencv-3.4.7 && mkdir build && cd build && \
    cmake -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j112 && make install && \
    echo 'include /usr/local/lib' | tee -a /etc/ld.so.conf && ldconfig 

# install pytorch
RUN wget https://download.pytorch.org/libtorch/cpu/libtorch-cxx11-abi-shared-with-deps-2.6.0%2Bcpu.zip && \
    unzip libtorch-cxx11-abi-shared-with-deps-2.6.0+cpu.zip -d /usr/local/lib/


# Set up fuzzers
RUN git clone https://gitee.com/zhangph12138/aflnet.git && \
    cd aflnet && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

RUN git clone https://gitee.com/zhangph12138/aflnwe.git && \
    cd aflnwe && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT


RUN git clone https://gitee.com/zhangph12138/aflml-v.git && \
    cd aflml-v && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT 


RUN git clone https://gitee.com/zhangph12138/aflml.git && \
    cd aflml && \
    cd ju && mkdir build && cd build && cmake .. && make && cd ../.. && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT



# Set up environment variables for AFLNet
ENV WORKDIR="/home/ubuntu/experiments"
ENV AFLNET="/home/ubuntu/aflnet"
ENV PATH="${PATH}:${AFLNET}:/home/ubuntu/.local/bin:${WORKDIR}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1
# env for opencv
ENV PKG_CONFIG_PATH=${PKG_CONFIG_PATH:-}:/usr/local/lib/pkgconfig



RUN mkdir $WORKDIR



COPY --chown=ubuntu:ubuntu e04bd3433f.patch ${WORKDIR}/e04bd3433f.patch
COPY --chown=ubuntu:ubuntu key ${WORKDIR}/key




# Copy the key folder from the Dockerfile directory to the container


# Set up environment variables for ASAN
ENV ASAN_OPTIONS='abort_on_error=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=1:detect_container_overflow=0:poison_array_cookie=0:malloc_fill_byte=0:max_malloc_fill_size=16777216'

# Download and compile OpenSSL for fuzzing
RUN cd ${WORKDIR} && \
    git clone https://gitee.com/hengke/openssl.git openssl && \
    cd openssl && \
    cp -r ${WORKDIR}/key ./ && \
    git checkout e04bd3433f && \
    patch -p1 < ${WORKDIR}/e04bd3433f.patch && \
    # CC=afl-clang-fast ./config no-shared --with-rand-seed=none && \
    # CC=afl-clang-fast make include/openssl/configuration.h include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
    # CC=afl-clang-fast make include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
    # AFL_USE_ASAN=1 CC=afl-clang-fast make -j112 apps/openssl $MAKE_OPT
    CC=afl-clang-fast ./config no-shared  && \
    CC=afl-clang-fast make $MAKE_OPT

    RUN echo "${WORKDIR}/openssl" >> /etc/ld.so.conf.d/libc.conf && ldconfig

# Download and compile OpenSSL for coverage analysis
RUN cd ${WORKDIR} && \
    git clone https://gitee.com/hengke/openssl.git openssl-gcov && \
    cd openssl-gcov && \
    cp -r ${WORKDIR}/key ./ && \
    git checkout e04bd3433f && \
    patch -p1 < ${WORKDIR}/e04bd3433f.patch && \
    # CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" ./config no-shared --with-rand-seed=none && \
    # # CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" make include/openssl/configuration.h include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \    
    # CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" make include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
    # CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" make -j112 apps/openssl $MAKE_OPT
    CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" ./config no-shared  && \
    # CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" make include/openssl/configuration.h include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \    
    # CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" make include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
    CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" make $MAKE_OPT

    RUN echo "${WORKDIR}/openssl-gcov" >> /etc/ld.so.conf.d/libc.conf && ldconfig



COPY --chown=ubuntu:ubuntu in-tls ${WORKDIR}/in-tls
COPY --chown=ubuntu:ubuntu tls.dict ${WORKDIR}/tls.dict
COPY --chown=ubuntu:ubuntu cov_script.sh ${WORKDIR}/cov_script
COPY --chown=ubuntu:ubuntu run.sh ${WORKDIR}/run



# # test
# RUN cd ${WORKDIR} && \
#     git clone https://gitee.com/zhangph12138/tlsfucker.git && \
#     cd tlsfucker && \
#     git checkout uncrypt && \
#     python3 -m pip install -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple --upgrade pip && \
#     pip config set global.index-url https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple && \
#     pip install --trusted-host mirrors.tuna.tsinghua.edu.cn -r ./requirements.txt