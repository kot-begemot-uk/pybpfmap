#!/usr/bin/python3


'''BPF Map ringbuf functional test
'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


from pybpfmap.bpfrecord import BPFMap, PinnedBPFMap
from pybpfmap.map_types import BPF_MAP_TYPE_RINGBUF

from os import unlink, chmod
import sys
import time
from struct import Struct, calcsize

PIN="/sys/fs/bpf/test_ringbuf"

#/* definition of a sample sent to user-space from BPF program */
#struct event {
#	int pid;
#	char comm[TASK_COMM_LEN];
#	char filename[MAX_FILENAME_LEN];
#};

PARSER_DEF = [("pid", "l"), ("task", "16s"), ("filename", "512s")]

def setup_ringbuf():
    '''Test Filtered map access'''
    m = PinnedBPFMap(
            PIN,
            map_type=BPF_MAP_TYPE_RINGBUF,
            name="rb",
            key_size=0,
            value_size=0,
            max_entries=256 * 1024)
    m.generate_parsers(None, PARSER_DEF)
    return m

def strip_nulls(arg):
    return arg[:arg.find(b'\0')]


def get_events(m):
    events = m.fetch_next(want_parsed=True)
    for event in events:
        event["task"] = strip_nulls(event["task"])
        event["filename"] = strip_nulls(event["filename"])
        print("{}".format(event))

m = setup_ringbuf()
while True:
    time.sleep(1)
    get_events(m)
