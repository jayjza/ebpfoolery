FROM ubuntu:jammy AS builder
ENV LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN :\
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --force-yes --no-install-recommends \
    iproute2 libbpf-dev llvm clang gh zip bison \
    build-essential cmake flex git libedit-dev \
    libllvm14 llvm-14-dev libclang-14-dev  zlib1g-dev libelf-dev libfl-dev \
    liblzma-dev libdebuginfod-dev arping netperf iperf nmap python3.10 \
    python3.10-venv python3.10-dev less

RUN mkdir /workspace
WORKDIR /workspace

RUN python3.10 -m venv /pythonenv3
COPY requirements.txt /workspace
RUN :\
    /pythonenv3/bin/python -m pip install setuptools wheel \
   && /pythonenv3/bin/python -m pip install --upgrade pip \
   && /pythonenv3/bin/python -m pip install --no-cache-dir -r /workspace/requirements.txt \
   && :