from bcc import BPF

def forge_ippers(personality, interface):
    flags = 0
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
    maptype = "percpu_array"

    # load BPF program
    b = BPF(text = open("personalities/{}.c".format(personality)).read(),
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
