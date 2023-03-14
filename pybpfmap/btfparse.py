'''Python presentation of BTF file format'''

# pybpfmap, Copyright (c) 2023 RedHat Inc
# pybpfmap, Copyright (c) 2023 Cambridge Greys Ltd

# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

from struct import Struct, calcsize
import sys

IS_64 = (int.bit_length(sys.maxsize) + 1 == 64)

BTF_KIND_INT            = 1
BTF_KIND_PTR            = 2
BTF_KIND_ARRAY          = 3
BTF_KIND_STRUCT         = 4
BTF_KIND_UNION          = 5
BTF_KIND_ENUM           = 6
BTF_KIND_FWD            = 7
BTF_KIND_TYPEDEF        = 8
BTF_KIND_VOLATILE       = 9
BTF_KIND_CONST          = 10
BTF_KIND_RESTRICT       = 11
BTF_KIND_FUNC           = 12
BTF_KIND_FUNC_PROTO     = 13
BTF_KIND_VAR            = 14
BTF_KIND_DATASEC        = 15
BTF_KIND_FLOAT          = 16
BTF_KIND_DECL_TAG       = 17
BTF_KIND_TYPE_TAG       = 18
BTF_KIND_ENUM64         = 19

KS_IS_SIZE = [BTF_KIND_INT, BTF_KIND_STRUCT, BTF_KIND_UNION, BTF_KIND_ENUM]

BTF_TYPE_TEMPLATE = "=III"
BTF_TYPE = Struct(BTF_TYPE_TEMPLATE)
BTF_SIZE = calcsize(BTF_TYPE_TEMPLATE)

BTF_ARRAY_TEMPLATE = "=III"
BTF_ARRAY = Struct(BTF_ARRAY_TEMPLATE)
BTF_A_SIZE = calcsize(BTF_ARRAY_TEMPLATE)

BTF_STRUCT_TEMPLATE = "=III"
BTF_STRUCT = Struct(BTF_STRUCT_TEMPLATE)
BTF_S_SIZE = calcsize(BTF_STRUCT_TEMPLATE)

BTF_ENUM_TEMPLATE = "=II"
BTF_ENUM = Struct(BTF_ENUM_TEMPLATE)
BTF_E_SIZE = calcsize(BTF_ENUM_TEMPLATE)

BTF_FP_TEMPLATE = "=II"
BTF_FP = Struct(BTF_FP_TEMPLATE)
BTF_FP_SIZE = calcsize(BTF_FP_TEMPLATE)

BTF_VAR_TEMPLATE = "=I"
BTF_VAR = Struct(BTF_VAR_TEMPLATE)
BTF_VAR_SIZE = calcsize(BTF_VAR_TEMPLATE)

BTF_SEC_TEMPLATE = "=III"
BTF_SEC = Struct(BTF_SEC_TEMPLATE)
BTF_SEC_SIZE = calcsize(BTF_SEC_TEMPLATE)

BTF_DECL_TAG_TEMPLATE = "=I"
BTF_DECL_TAG = Struct(BTF_DECL_TAG_TEMPLATE)
BTF_DECL_TAG_SIZE = calcsize(BTF_DECL_TAG_TEMPLATE)


def fetch_str(buff, str_off):
    '''Fetch a zero_terminated string form the buffer, adjusting given offset'''
    pos = loc = str_off
    while not buff[pos] == 0:
        pos = pos + 1
    return str(buff[loc:pos], encoding="ascii")


class BTFRecord():
    '''Class representing a single BTF Record'''

    JUMP_TABLE = {
        BTF_KIND_ARRAY: array_init,
        BTF_KIND_STRUCT: struct_init,
        BTF_KIND_UNION: struct_init,
        BTF_KIND_ENUM: enum_init,
        BTF_KIND_FUNC_PROTO: func_proto_init,
        BTF_KIND_VAR: var_init,
        BTF_KIND_DATASEC: datasec_init,
        BTF_KIND_DECL_TAG: decl_tag_init,
    }

    def __init__(self, info):

        pos = info["pos"]
        buff = info["buffer"]

        (name_off, info, size_type) = BTF_TYPE.unpack(buff[pos:pos + BTF_SIZE])

        pos += BTF_SIZE

        self.desc = {
            "name" : fetch_str(buff, name_off),
            "vlen" : info & 0xFFFF,
            "kind" : (info & (0xF << 24)) >> 24,
            "kind_flag" : not (info & (1 << 31)) == 0
        }

        if self.desc["kind"] in KS_IS_SIZE:
            self.desc["size"] = size_type
        else:
            self.desc["type"] = size_type

        self.JUMP_TABLE[self.desc["kind"]](pos, buff)

    def array_init(self, pos, buff):
        '''ARRAY init'''
        loc = pos + BTF_SIZE
        (atype, index_type, nelems) = BTF_ARRAY.unpack(buff[loc : loc + BTF_A_SIZE])
        self.desc["array"] = {
            "type" : atype,
            "index_type" : index_type,
            "nelems" : nelems
        }

    def struct_init(self, pos, buff):
        '''Struct/Union init'''
        for count in range(0, self.desc["vlen"]):
            loc = pos + BTF_SIZE + count * BTF_S_SIZE
            (name_off, stype, offset) = BTF_STRUCT.unpack(buff[loc:loc + BTF_S_SIZE])
            self.desc["members"] = {
                "name" : fetch_str(buff, name_off),
                "type" : stype,
                "offset" : offset
            }

    def enum_init(self, pos, buff):
        '''Enum Init'''
        for count in range(0, self.desc["vlen"]):
            loc = pos + BTF_SIZE + count * BTF_E_SIZE
            (name_off, val) = BTF_ENUM.unpack(buff[loc:loc + BTF_E_SIZE])
            self.desc["values"] = {
                "name" : fetch_str(buff, name_off),
                "value" : val
            }

    def func_proto_init(self, pos, buff):
        '''Func proto init'''
        for count in range(0, self.desc["vlen"]):
            loc = pos + BTF_SIZE + count * BTF_FP_SIZE
            (name_off, ftype) = BTF_FP.unpack(buff[loc:loc + BTF_FP_SIZE])
            self.desc["params"] = {
                "name" : fetch_str(buff, name_off),
                "type" : ftype
            }

    def var_init(self, pos, buff):
        '''Var init'''
        loc = pos + BTF_SIZE
        (linkage) = BTF_VAR.unpack(buff[loc:loc + BTF_VAR_SIZE])
        self.desc["linkage"] = linkage

    def datasec_init(self, pos, buff):
        '''Datasec init'''
        for count in range(0, self.desc["vlen"]):
            loc = pos + BTF_SIZE + count * BTF_SEC_SIZE
            (stype, offset, size) = BTF_SEC.unpack(buff[loc:loc + BTF_SEC_SIZE])
            self.desc["members"] = {
                "type" : stype,
                "offset" : offset,
                "size" : size
            }

    def decl_tag_init(self, pos, buff):
        '''Tag Init'''
        loc = pos + BTF_SIZE
        (idx) = BTF_DECL_TAG.unpack(buff[loc:loc + BTF_DECL_TAG_SIZE])
        self.desc["component_idx"] = idx
