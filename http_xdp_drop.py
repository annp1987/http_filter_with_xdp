#!/usr/bin/env python
#
# Copyright (c) annp.cs51@gmail.com
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
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

mode = BPF.XDP

# load BPF program
b = BPF(src_file="./xdp_drop.c", cflags=["-w"])

fn = b.load_func("xdp_prog1", mode)

# attach xdp
b.attach_xdp(device, fn, flags)

# get map table
action_map = b.get_table("action_map")

print("Printing dropping!")
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, flags)
