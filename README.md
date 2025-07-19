# README

This repository contains various projects related to deep learning-based fuzzing and protocol model learning. Below is a brief description of each directory:

## Directory Structure

- **afldl**: 
  - This directory contains the implementation of AFLLDL, which is a state-aware fuzzing tool that utilizes deep learning techniques. It aims to improve the efficiency and effectiveness of fuzzing by leveraging state information.

- **afldl-v**: 
  - This directory contains the variant of AFLLDL where the state-aware module has been removed. It serves as a baseline for comparison with the full AFLLDL implementation.

- **ipsec-learner**: 
  - This directory contains the implementation of IPSEC-Learner, which focuses on learning models of the IPSEC protocol. The goal is to understand and model the behavior of the protocol using machine learning techniques.

- **profuzzbench**: 
  - This directory contains the Profuzzbench benchmark suite, which is used for evaluating the performance of different fuzzing tools and techniques. It provides a standardized set of benchmarks for comparing the effectiveness of various approaches.

- **state_siamese**: 
  - This directory contains the implementation of State-Siamese, which is a model designed for clustering memory snapshots based on their states. It uses Siamese networks to learn representations that can effectively group similar states together.

- **tls-learner**: 
  - This directory contains the implementation of TLS-Learner, which focuses on learning models of the TLS protocol. Similar to IPSEC-Learner, it aims to understand and model the behavior of the TLS protocol using machine learning techniques.

- **README.md**: 
  - This file provides an overview of the repository and describes the purpose and contents of each directory.


## Environment configuration

All code is run in Ubuntu 20.04.


## Usage

Each directory contains its own documentation and scripts for running the respective projects. Please refer to the individual README files within each directory for detailed instructions on how to use and run the projects.


## example for openssl

1. learn State Machine

make openssl

```

git clone https://gitee.com/zhangph12138/openssl.git
cd openssl 
git checkout 0437435a 
CC=clang ./config no-shared --with-rand-seed=none && \
CC=clang make include/openssl/configuration.h include/openssl/opensslv.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
CC=clang make apps/openssl

```

start openssl 

```
openssl s_server -cert key/server.cer -key key/deserver.key -CAfilekey/ca.cer -keylogfile key/key.log -HTTP


```

learning

```

python3 tls12_ltlfuzzing.py

```

The sample output can be found in tls-learner\dots\openssl-111f-tls12.dot.


2. get dataset

```
python3 generate.py
```

training model

```
& python train.py --epochs 300 --batch_size 64 --learning_rate 0.001 --model "resnet50" --dataset_name "openssl12_sample100_state6" --dataset_path "data\\openssl12" --save_path "./" --interval 10 --num_classes 6 --protocol "openssl12"
```


3 fuzzing 

you can use profuzzbench to run afldl


```
cd profuzzbench\subjects\TLS\OpenSSL\openssl-111w

docker build . -t openssl-fuzz:111w --progress=plain

docker run  --privileged -it   openssl-fuzz:111w  /bin/bash


cd /home/ubuntu/afldl

afl-fuzz -d -i /home/ubuntu/experiments/in-tls -x /home/ubuntu/experiments/tls.dict -o out-openssl-aflnet \
-N tcp://127.0.0.1/4433 -P TLS -D 10000 -q 3 -s 3 -E -K -R -W 100 -t 5000+ -m none ./apps/openssl s_server -key key.pem -cert cert.pem -4 -naccept 1 -no_anti_replay


```



