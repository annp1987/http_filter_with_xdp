#!/usr/bin/env python
#
# Copyright (c) annp.cs51@gmail.com
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys

# XDP_FLAGS_SKB_MODE
flags = 2


def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

#mode = BPF.XDP
mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_PASS"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_OK"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(src_file="./xdp_drop.c", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])

fn = b.load_func("xdp_prog1", mode)

if mode == BPF.XDP:
    # attach xdp
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

# get map table
action_map = b.get_table("action_map")

print("Printing dropping!")
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()