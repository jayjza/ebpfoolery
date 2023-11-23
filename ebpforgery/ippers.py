#! /usr/bin/env python
#
# ippers.py

from bcc import BPF
import sys

flags = 0
def usage():
    print(f"""
          Usage: {sys.argv[0]} <personality> <network_interface>
            e.g. {sys.argv[0]} win2016 eth0
          """)
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

personality = sys.argv[1]
interface = sys.argv[2]

ret = "XDP_DROP"
ctxtype = "xdp_md"
maptype = "percpu_array"


# load BPF program
b = BPF(text = open("{}.c".format(personality)).read(),
        cflags=["-w",
                "-DRETURNCODE=%s" % ret,
                "-DCTXTYPE=%s" % ctxtype,
                "-DMAPTYPE=\"%s\"" % maptype]
    )

fn = b.load_func("xdp_prog1", BPF.XDP)
b.attach_xdp(interface, fn, flags)

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        break

    print(f"task={task}, pid={pid}, msg={msg}")

b.remove_xdp(interface)
