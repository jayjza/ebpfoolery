from bcc import BPF
from os import path

# We likely make this a list of the personalities directory
AVAILABLE_PERSONALITIES = ['win2016']

def forge_ippers(personality, interface):
    flags = 0
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
    maptype = "percpu_array"

    # load BPF program

    personalities_dir = path.join(path.dirname(__file__), 'personalities')
    b = BPF(text = open("{}/{}.c".format(personalities_dir, personality)).read(),
            cflags=["-w",
                    "-DRETURNCODE=%s" % ret,
                    "-DCTXTYPE=%s" % ctxtype,
                    "-DMAPTYPE=\"%s\"" % maptype]
        )

    fn = b.load_func("xdp_prog1", BPF.XDP)
    b.attach_xdp(interface, fn, flags)
    print("Ippers is in place.")
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            continue
        except KeyboardInterrupt:
            break

        print(f"task={task}, pid={pid}, msg={msg}")

    b.remove_xdp(interface)
