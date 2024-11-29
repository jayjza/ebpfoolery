FROM ubuntu:jammy AS builder
ENV LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN :\
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y --force-yes --no-install-recommends \
    iproute2 libbpf-dev llvm clang gh zip bison \
    build-essential cmake flex git libedit-dev \
    libllvm14 llvm-14-dev libclang-14-dev  zlib1g-dev libelf-dev libfl-dev \
    liblzma-dev libdebuginfod-dev arping netperf iperf nmap

RUN mkdir /workspace
WORKDIR /workspace
