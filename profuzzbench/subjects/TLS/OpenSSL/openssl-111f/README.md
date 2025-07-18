Please carefully read the [main README.md](../../../README.md), which is stored in the benchmark's root folder, before following this subject-specific guideline.

# Fuzzing OpenSSL TLS server with AFLNet and AFLnwe and AFLml
Please follow the steps below to run and collect experimental results for OpenSSL.

export PFBENCH=$(pwd)
export PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis

## Step-1. Build a docker image
The following commands create a docker image tagged openssh. The image should have everything available for fuzzing and code coverage calculation.

```bash
export PFBENCH=$(pwd)
export PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis
cd $PFBENCH
cd subjects/TLS/OpenSSL/openssl-111f
docker build . -t openssl-fuzz:111f --progress=plain
```

## Step-2. Run fuzzing
The following commands run 4 instances of AFLNet and 4 instances of AFLnwe to simultaenously fuzz OpenSSL in 60 minutes.

```bash

export PFBENCH=$(pwd)
export PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis

cd $PFBENCH
mkdir results-openssl-111f

docker rm -f $(docker ps -aq)

profuzzbench_exec_common.sh openssl-fuzz:111f 4 results-openssl-111f aflnet out-openssl-aflnet "-P TLS -D 10000 -q 3 -s 3 -E -K -R -W 100 -t 5000+ -m none" 36000 5 &
profuzzbench_exec_common.sh openssl-fuzz:111f 4 results-openssl-111f aflnwe out-openssl-aflnwe "-D 10000 -K -W 100 -t 5000+ -m none" 36000 5 &
profuzzbench_exec_common.sh openssl-fuzz:111f 4 results-openssl-111f aflml out-openssl-aflml "-P TLS -D 10000 -q 3 -s 3 -E -K -R -W 100 -t 5000+ -m none" 36000 5 
```

## Step-3. Collect the results
The following commands collect the  code coverage results produced by AFLNet and AFLnwe and save them to results.csv.

```bash
cd $PFBENCH/results-openssl-111f

profuzzbench_generate_csv.sh openssl 4 aflnet results.csv 0
profuzzbench_generate_csv.sh openssl 4 aflnwe results.csv 1
profuzzbench_generate_csv.sh openssl 4 aflml  results.csv 2

cal_improvement.py -i -r
esults.csv -t aflml -o compare.csv

```

## Step-4. Analyze the results
The results collected in step 3 (i.e., results.csv) can be used for plotting. Use the following command to plot the coverage over time and save it to a file.

```
cd $PFBENCH/results-openssl-111f

profuzzbench_plot.py -i results.csv -p openssl -r 4 -c 1440 -s 1 -o cov_over_time.png
```
# run
cd /home/ubuntu/experiments
cd openssl


afl-fuzz -d -i /home/ubuntu/experiments/in-tls -x /home/ubuntu/experiments/tls.dict -o out-openssl-aflnet \
-N tcp://127.0.0.1/4433 -P TLS -D 10000 -q 3 -s 3 -E -K -R -W 100 -t 5000+ -m none ./apps/openssl s_server -key key.pem -cert cert.pem -4 -naccept 1 -no_anti_replay

export PFBENCH=$(pwd)
export PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis
cd $PFBENCH
cd subjects/TLS/OpenSSL
docker build . -t openssl



docker run -it openssl /bin/sh