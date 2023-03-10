#!/usr/bin/python3


'''BPF Map parser test
'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.


from pybpfmap.bpfrecord import BPFRecord

from nose.tools import ok_ as assert_
from nose.tools import raises
from nose.tools import assert_equal
from nose.tools import assert_is_none

from pybpfmap.bpfrecord import BPFRecord

def test_create():
    '''Create a record parser'''

    p = BPFRecord([("field1", "B"), ("field2", "B")])

    assert_equal(p.template, "=BB")
    assert_equal(p.json_template[0][0], "field1")

def test_unpack():

    p = BPFRecord([("field1", "B"), ("field2", "B")])
    result = p.unpack(bytes([17, 46]))
    assert_equal(result["field1"], 17)
    assert_equal(result["field2"], 46)

def test_pack():

    p = BPFRecord([("field1", "B"), ("field2", "B")])
    result = p.pack({"field1":17, "field2":46})
    assert_equal(result[0], 17)
    assert_equal(result[1], 46)
