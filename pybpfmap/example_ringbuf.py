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
TASK_COMM_LEN = 16
MAX_FILENAME_LEN = 512

#/* definition of a sample sent to user-space from BPF program */
#struct event {
#	int pid;
#	char comm[TASK_COMM_LEN];
#	char filename[MAX_FILENAME_LEN];
#};

PATTERN_32 = "=l16s512s"

EVENT_PARSER_32 = Struct(PATTERN_32)

event_parser = EVENT_PARSER_32

def setup_ringbuf():
    '''Test Filtered map access'''
    m = PinnedBPFMap(
            PIN,
            map_type=BPF_MAP_TYPE_RINGBUF,
            name="rb",
            key_size=0,
            value_size=0,
            max_entries=256 * 1024)
    return m


def get_events(m):
    events = m.fetch_next()
    for event in events:
        (pid, comm, filename) = event_parser.unpack(event)
        print("{} {} {}".format(pid, comm.rstrip(b'\0'), filename.rstrip(b'\0')))

m = setup_ringbuf()
while True:
    time.sleep(1)
    get_events(m)
