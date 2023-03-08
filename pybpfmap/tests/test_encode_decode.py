#!/usr/bin/python3


'''BPF Map parser test
'''

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
    result = p.parse(bytes([17, 46]))
    assert_equal(result["field1"], 17)
    assert_equal(result["field2"], 46)
