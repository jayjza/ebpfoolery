# eBPForgery

<img src="docs/logo.png" width="800" style="float: left"> 
eBPForgery brings the stealthy OS fooling of Canary to the world of eBPF.


# Overview

Thinkst Canary offers a device that mimics real life targets to an incredible degree of accuracy. One of painstaking methods to fooling attackers into interaction with a machine, is to mimic certain OS IP Stack personalities (IPPERS). eBPForgery offers this capability with the added bonus of portability (through the usage of eBPF).

eBPForgery uses the magic of eBPF (and XDP) to mimic certain OS IP Stacks (currently Windows 2016 and Playstation 4) meaning that if an attacker nmaps your Ubuntu machine, you can choose what OS they are going to get back. 

# Usage
## View Personalities
```
./ebpforged -l
```

## Running
```
./ebpforged -i <network_interface> -p <personality>
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


# Potential Issues:

1. Missing BCC after above steps still

Problem: In poetry env, you may not be able to access BCC and get the error:
```
(ebpforgery-py3.10) ➜  ebpforgery git:(main) ./ebpforged -p win2016 -i ens160
Traceback (most recent call last):
  File "/home/ubuntu/ebpforgery/ebpforge", line 23, in <module>
    from ebpforgery import forge_ippers, AVAILABLE_PERSONALITIES
  File "/home/ubuntu/ebpforgery/ebpforgery/__init__.py", line 1, in <module>
    from bcc import BPF
ModuleNotFoundError: No module named 'bcc'
```

Solution:
In your venv: `poetry config virtualenvs.options.system-site-packages true`
Using system working python3:
```
➜  ebpforgery git:(main) ✗ python3 -m site
sys.path = [
    '/home/j/ebpforgery',
    '/usr/lib/python310.zip',
    '/usr/lib/python3.10',
    '/usr/lib/python3.10/lib-dynload',
    '/usr/local/lib/python3.10/dist-packages',
    '/usr/lib/python3/dist-packages',
    '/usr/lib/python3/dist-packages/bcc-0.28.0+003b0037-py3.10.egg',
]
```
Notice the `bcc-*.egg`.

In your venv, run the same to see the difference:
```
(ebpforgery-py3.10) ➜  ebpforgery git:(main) ✗ python -m site
sys.path = [
    '/home/j/ebpforgery',
    '/usr/lib/python310.zip',
    '/usr/lib/python3.10',
    '/usr/lib/python3.10/lib-dynload',
    '/home/j/.cache/pypoetry/virtualenvs/ebpforgery-iDpkqNNH-py3.10/lib/python3.10/site-packages',
]
```

We can take it further check using:
```
(ebpforgery-py3.10) ➜  ebpforgery git:(main) python3 -c "import bcc as _; print(_.__file__)"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'bcc'
(ebpforgery-py3.10) ➜  ebpforgery git:(main) exit
➜  ebpforgery git:(main) python3 -c "import bcc as _; print(_.__file__)"
/usr/lib/python3/dist-packages/bcc-0.28.0+bc9b43a0-py3.10.egg/bcc/__init__.py
```
Notice how the system find the files and displays its location
