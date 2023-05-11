#!/usr/bin/python3


'''BPF Map functional test
'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


from pybpfmap.bpfrecord import BPFMap, PinnedBPFMap
from pybpfmap.filtered_record import FilteredBPFMap
from pybpfmap.map_types import BPF_MAP_TYPE_HASH

from nose.tools import ok_ as assert_
from nose.tools import raises
from nose.tools import assert_equal
from nose.tools import assert_is_none
from os import unlink, chmod
import sys
import time

TESTKEY_HASH = {"uid": 1, "gid": 1}
TESTDATA_ARRAY = {"data": [0, 1, 2, 3, 4, 5, 6, 7]}

PIN="/sys/fs/bpf/test_f".encode("ascii")

def test_filtered():
    '''Test Filtered map access'''

    m = BPFMap(-1, BPF_MAP_TYPE_HASH, "test_perm".encode("ascii"), 16, 64, 256, create=True)
    m.generate_parsers([("uid", "Q"), ("gid", "Q")], [("data", ["Q","Q","Q","Q","Q","Q","Q","Q"])])
    assert_(m.update_elem(TESTKEY_HASH, TESTDATA_ARRAY))
    try:
        unlink(PIN)
    except OSError:
        pass
    assert_(m.pin_map(PIN))
    del m

    chmod(PIN, 0o775)

    p = FilteredBPFMap(PIN, {"data":["X","X","W","X","X","X","X","X"]}, map_type=BPF_MAP_TYPE_HASH, name="retest_perm", key_size=16, value_size=64, max_entries=256)

    p.generate_parsers([("uid", "Q"), ("gid", "Q")], [("data", ["Q","Q","Q","Q","Q","Q","Q","Q"])])
    l = p.lookup_elem(TESTKEY_HASH)
    
    assert_is_none(l["data"][0])
    assert_is_none(l["data"][1])
    assert_is_none(l["data"][3])
    assert_is_none(l["data"][4])
    assert_is_none(l["data"][5])
    assert_is_none(l["data"][6])
    assert_is_none(l["data"][7])

    assert_equal(l["data"][2], TESTDATA_ARRAY["data"][2])
   

test_filtered()
