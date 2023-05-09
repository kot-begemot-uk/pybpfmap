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
TESTKEY_HASH = {"uid": 1, "gid": 1}
TESTDATA_HASH = {"data0": 0, "data1": 1,"data2": 2, "data3": 3,"data4": 4, "data5": 5,"data6": 6, "data7": 7}

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
    l = m.lookup_elem(TESTKEY)
    assert_equal(l,TESTDATA)
    
    
def test_elements():
    '''Create a record parser for high level respresntation'''

    m = BPFMap(1, BPF_MAP_TYPE_HASH, "test_elem".encode("ascii"), 16, 64, 256, create=True)
    m.generate_parsers([("uid", "Q"), ("gid", "Q")], [("data0", "Q"), ("data1", "Q"),("data2", "Q"),("data3", "Q"),("data4", "Q"),("data5", "Q"),("data6", "Q"), ("data7", "Q")])
    assert_(m.update_elem(TESTKEY_HASH, TESTDATA_HASH))
    l = m.lookup_elem(TESTKEY_HASH, want_hash=True)
    assert_equal(l["data0"],TESTDATA_HASH["data0"])
    assert_equal(l["data1"],TESTDATA_HASH["data1"])
    assert_equal(l["data2"],TESTDATA_HASH["data2"])
    assert_equal(l["data3"],TESTDATA_HASH["data3"])
    assert_equal(l["data4"],TESTDATA_HASH["data4"])
    assert_equal(l["data5"],TESTDATA_HASH["data5"])
    assert_equal(l["data6"],TESTDATA_HASH["data6"])
    assert_equal(l["data7"],TESTDATA_HASH["data7"])
    


