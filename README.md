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
  liblzma-dev libdebuginfod-dev arping netperf iperf nmap
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

## Development
This project uses Python Poetry.
[ https://python-poetry.org/docs/master/#installing-with-the-official-installer ]
Install Python Poetry using:
```
curl -sSL https://install.python-poetry.org | python3 -
```

You can read over [ https://python-poetry.org/docs/master/#enable-tab-completion-for-bash-fish-or-zsh ] to enable
tab completion.

Once Python Poetry is installed. You can setup using:
```
cd ebpforgery
poetry install
```

If you would like to add a new dependency:
```
poetry add <package_name>
```

If you would like to hop into the virtual environment, use:
```
poetry shell
```

If you would like to run the program using the virtualenv, but not in the shell, use:
```
poetry run python3 ...
```
