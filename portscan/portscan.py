#!/usr/bin/env python3
from bcc import BPF
import socket
import os
from time import sleep
import sys

def main():
    b = BPF(src_file="portscan.bpf.c")
    interface = "ens160"

    # XDP will be the first program hit when a packet is received ingress
    fx = b.load_func("xdp", BPF.XDP)
    BPF.attach_xdp(interface, fx, 0)

    try:
        b.trace_print()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
