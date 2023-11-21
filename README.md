# Prerequsites
 - Ubuntu 22.04


# Installation

## Updating Ubuntu
```
sudo apt-get update
sudo apt-get upgrade
```

## Installing Pre-requisites

There is a number of pre-requisites that must be installed for the development:

```
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
```

## Installing & Compiling bcc
[ https://github.com/iovisor/bcc/blob/master/INSTALL.md#install-build-dependencies-1 ]
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```
