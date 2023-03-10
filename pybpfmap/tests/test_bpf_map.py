#!/usr/bin/python3


'''BPF Map functional test
'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


from pybpfmap.bpfrecord import BPFMap
from pybpfmap.map_types import BPF_MAP_TYPE_HASH

from nose.tools import ok_ as assert_
from nose.tools import raises
from nose.tools import assert_equal
from nose.tools import assert_is_none
from os import unlink

TESTSEQ = "0102030405060708090a0b0c0d0e0f00"
TESTKEY = bytes.fromhex(TESTSEQ)
TESTDATA = bytes.fromhex(TESTSEQ + TESTSEQ + TESTSEQ + TESTSEQ)


def test_create():
    '''Create a map'''

    m = BPFMap(1, BPF_MAP_TYPE_HASH, "test_create".encode("ascii"), 16, 64, 256, create=True)

def test_pin():
    '''Pin a map'''

    m = BPFMap(1, BPF_MAP_TYPE_HASH, "test_pin".encode("ascii"), 16, 64, 256, create=True)
    try:
        unlink("/sys/fs/bpf/test_pin")
    except OSError:
        pass
    assert_(m.pin_map("/sys/fs/bpf/test_pin".encode("ascii")))
    unlink("/sys/fs/bpf/test_pin")
    
   
def test_elements():
    '''Create a record parser'''

    m = BPFMap(1, BPF_MAP_TYPE_HASH, "test_elem".encode("ascii"), 16, 64, 256, create=True)
    assert_(m.update_elem(TESTKEY, TESTDATA))
    print(TESTDATA.hex())
    l = m.lookup_elem(TESTKEY)
    print(l.hex())
    assert_equal(m.lookup_elem(TESTKEY),TESTDATA)
    
    


