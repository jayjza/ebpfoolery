# eBPFooling

<img src="docs/logo.png" width="800" style="float: left">
eBPFooling brings the stealthy OS fooling of Canary to the world of eBPF.


# Overview

Thinkst Canary offers a device that mimics real life targets to an incredible degree of accuracy. One of painstaking methods to fooling attackers into interaction with a machine, is to mimic certain OS IP Stack personalities (IPPERS). eBPFooling offers this capability with the added bonus of portability (through the usage of eBPF).

eBPFooling uses the magic of eBPF (and XDP) to mimic certain OS IP Stacks (currently Windows 2016 and Playstation 4) meaning that if an attacker nmaps your Ubuntu machine, you can choose what OS they are going to get back.

# Usage
```
./ebpfooling
Usage: ebpfooling [OPTIONS] COMMAND [ARGS]...

  Welcome to some Tom eBPFoolery

Options:
  --help  Show this message and exit.

Commands:
  ippers    Manage ippers functionality
  portscan  Manage portscan functionality
```
## View Personalities
```
./ebpfooling ippers available
```

## Enabling Ippers
```
./ebpfooling ippers enable <PERSONALITY> <INTERFACE>
```

## Enabling Portscan
```
./ebpfooling portscan enable <INTERFACE>
```

# Installation
## Prerequsites
 - Ubuntu 22.04

## Updating Ubuntu
```
sudo apt-get update
sudo apt-get upgrade
```

## Installing Pre-requisites

There is a number of pre-requisites that must be installed for the development:

```
sudo apt install -y zip iproute2 libbpf-dev llvm clang gh zip bison \
    build-essential cmake flex git libedit-dev \
    libllvm14 llvm-14-dev libclang-14-dev  zlib1g-dev libelf-dev libfl-dev \
    liblzma-dev libdebuginfod-dev arping netperf iperf nmap python3.10 \
    python3.10-venv python3.10-dev
```

## Development Using Docker
This project has a dev container that uses a custom docker image which has everything there for you.
1. Simply open the project in vs-code
2. Allow vs-code to "Reopen in a container"
3. Have fun!

## Development Using Python Poetry
This project uses Python Poetry.
[ https://python-poetry.org/docs/master/#installing-with-the-official-installer ]
Install Python Poetry using:
```
curl -sSL https://install.python-poetry.org | python3 -
```

You can read over [ https://python-poetry.org/docs#enable-tab-completion-for-bash-fish-or-zsh ] to enable
tab completion.

Once Python Poetry is installed. You can setup using:
```
cd eBPFooling
poetry config virtualenvs.options.system-site-packages true
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
