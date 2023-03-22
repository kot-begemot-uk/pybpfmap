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

BTFKIND_VOID           = 0
BTFKIND_INT            = 1
BTFKIND_PTR            = 2
BTFKIND_ARRAY          = 3
BTFKIND_STRUCT         = 4
BTFKIND_UNION          = 5
BTFKIND_ENUM           = 6
BTFKIND_FWD            = 7
BTFKIND_TYPEDEF        = 8
BTFKIND_VOLATILE       = 9
BTFKIND_CONST          = 10
BTFKIND_RESTRICT       = 11
BTFKIND_FUNC           = 12
BTFKIND_FUNC_PROTO     = 13
BTFKIND_VAR            = 14
BTFKIND_DATASEC        = 15
BTFKIND_FLOAT          = 16
BTFKIND_DECL_TAG       = 17
BTFKIND_TYPE_TAG       = 18
BTFKIND_ENUM64         = 19


BTFHEADER_TEMPLATE = "=HBBIIIII"
BTFHEADER = Struct(BTFHEADER_TEMPLATE)
BTFHEADER_SIZE = calcsize(BTFHEADER_TEMPLATE)

KS_IS_SIZE = [BTFKIND_INT, BTFKIND_STRUCT, BTFKIND_UNION,
              BTFKIND_ENUM, BTFKIND_ENUM64, BTFKIND_FLOAT,
              BTFKIND_DATASEC]

NO_VALID_NAME = [BTFKIND_PTR, BTFKIND_ARRAY,
                 BTFKIND_VOLATILE, BTFKIND_CONST,
                 BTFKIND_RESTRICT, BTFKIND_FUNC_PROTO]

BTFTYPE_TEMPLATE = "=III"
BTFTYPE = Struct(BTFTYPE_TEMPLATE)
BTFSIZE = calcsize(BTFTYPE_TEMPLATE)

BTFARRAY_TEMPLATE = "=III"
BTFARRAY = Struct(BTFARRAY_TEMPLATE)
BTFA_SIZE = calcsize(BTFARRAY_TEMPLATE)

BTFSTRUCT_TEMPLATE = "=III"
BTFSTRUCT = Struct(BTFSTRUCT_TEMPLATE)
BTFS_SIZE = calcsize(BTFSTRUCT_TEMPLATE)

BTFENUM_TEMPLATE = "=II"
BTFENUM = Struct(BTFENUM_TEMPLATE)
BTFE_SIZE = calcsize(BTFENUM_TEMPLATE)

BTFFP_TEMPLATE = "=II"
BTFFP = Struct(BTFFP_TEMPLATE)
BTFFP_SIZE = calcsize(BTFFP_TEMPLATE)

BTFVAR_TEMPLATE = "=I"
BTFVAR = Struct(BTFVAR_TEMPLATE)
BTFVAR_SIZE = calcsize(BTFVAR_TEMPLATE)

BTFSEC_TEMPLATE = "=III"
BTFSEC = Struct(BTFSEC_TEMPLATE)
BTFSEC_SIZE = calcsize(BTFSEC_TEMPLATE)

BTFDECL_TAG_TEMPLATE = "=I"
BTFDECL_TAG = Struct(BTFDECL_TAG_TEMPLATE)
BTFDECL_TAG_SIZE = calcsize(BTFDECL_TAG_TEMPLATE)

BTFE64_TEMPLATE = "=III"
BTFE64 = Struct(BTFE64_TEMPLATE)
BTFE64_SIZE = calcsize(BTFE64_TEMPLATE)

# We need to disable this because of using a class per
# BTF type. While this results in rather ugly python,
# it may prove useful later when we add parsing, templates,
# etc.

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-arguments
# pylint: disable=unused-variable

class BTFBase():
    '''Class representing a single BTF Record'''
    # pylint: disable=too-many-instance-attributes
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        self.tid = kind
        self.bufsize = BTFSIZE
        self.btf = btf
        self.has_size = False
        self.name = None
        if not kind in NO_VALID_NAME:
            if name is not None:
                self.name = name
            else:
                if name_off > 0:
                    self.name = btf.resolve_str(name_off)

        self.name_off = name_off
        self.vlen = vlen
        self.tid_flag = kind_flag
        if self.tid in KS_IS_SIZE:
            self.has_size = True
            self.size = size_or_type
        else:
            self.type = size_or_type

        self.subrecords = []
        self.subname = "subrecords"

    def __repr__(self):
        '''Printable representation'''

        ret = ""
        if self.tid == BTFKIND_CONST:
            try:
                ret = "const:{}".format(self.type.name)
            except AttributeError:
                pass
        elif self.tid == BTFKIND_PTR:
            try:
                ret = "ptr: {}".format(self.type.name)
            except AttributeError:
                pass
        else:
            if self.name is None:
                ret = "name_off: {}, kind: {}".format(
                        self.name_off, self.tid)
            else:
                ret = "name: {}, kind: {}".format(
                        self.name, self.tid)
            if self.has_size:
                ret += ", size: {}".format(self.size)
            else:
                if self.tid == BTFKIND_FUNC_PROTO:
                    ret += ", refer type: {}".format(self.type)
                else:
                    try:
                        ret += ", type: {}".format(self.type.name)
                    except AttributeError:
                        pass
            if len(self.subrecords) > 0:
                ret += ", {}: {}".format(self.subname, self.subrecords)
        return ret

class BTFGeneric(BTFBase):
    '''Generic (no subrecords) init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)


class BTFArray(BTFBase):
    '''ARRAY init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize
        (atype, index_type, nelems) = BTFARRAY.unpack(btf.buff[loc : loc + BTFA_SIZE])
        self.subrecords.append({
            "type" : atype,
            "index_type" : index_type,
            "nelems" : nelems
        })
        self.subname = "members"
        self.bufsize += BTFA_SIZE

class BTFStruct(BTFBase):
    '''Struct/Union init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type,
                         name=name, name_off=name_off, btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFS_SIZE * self.vlen

        self.subname = "members"

        for count in range(0, self.vlen):
            (name_off, stype, offset) = BTFSTRUCT.unpack(btf.buff[loc:loc + BTFS_SIZE])
            self.subrecords.append({
                "name" : self.btf.resolve_str(name_off),
                "type" : stype,
                "offset" : offset
            })
            loc += BTFS_SIZE

class BTFEnum(BTFBase):
    '''Enum Init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False, size_or_type=0,
                 name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFE_SIZE * self.vlen

        self.subname = "values"

        for count in range(0, self.vlen):
            (name_off, val) = BTFENUM.unpack(btf.buff[loc:loc + BTFE_SIZE])
            self.subrecords.append({
                "name" : self.btf.resolve_str(name_off),
                "value" : val
            })
            loc += BTFE_SIZE

class BTFFuncProto(BTFBase):
    '''Func proto init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off, btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFFP_SIZE * self.vlen

        self.subname = "params"

        for count in range(0, self.vlen):
            (name_off, ftype) = BTFFP.unpack(btf.buff[loc:loc + BTFFP_SIZE])
            self.subrecords.append({
                "name" : self.btf.resolve_str(name_off),
                "type" : ftype
            })
            loc += BTFFP_SIZE

class BTFVar(BTFBase):
    '''Var init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):

        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFVAR_SIZE

        self.subname = "linkage"
        (linkage) = BTFVAR.unpack(btf.buff[loc:loc + BTFVAR_SIZE])
        self.subrecords.append({"linkage":linkage})

class BTFDataSec(BTFBase):
    '''Datasec init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFSEC_SIZE * self.vlen

        self.subname = "members"

        for count in range(0, self.vlen):
            (stype, offset, size) = BTFSEC.unpack(btf.buff[loc:loc + BTFSEC_SIZE])
            self.subrecords.append({
                "type" : stype,
                "offset" : offset,
                "size" : size
            })
            loc += BTFSEC_SIZE

class BTFEnum64(BTFBase):
    '''Enum 64 init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False, size_or_type=0,
                 name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFE64_SIZE * self.vlen

        self.subname = "values"

        for count in range(0, self.vlen):
            (name_off, lo32, hi32) = BTFE64.unpack(btf.buff[loc:loc + BTFE64_SIZE])
            self.subrecords.append({
                "name" : name_off,
                "lo32" : lo32,
                "high32" : hi32
            })
            loc += BTFE64_SIZE

class BTFDeclTag(BTFBase):
    '''Tag Init'''
    def __init__(self, kind=None, vlen=0, kind_flag=False,
                 size_or_type=0, name=None, name_off=0, btf=None):
        super().__init__(kind=kind, vlen=vlen, kind_flag=kind_flag,
                         size_or_type=size_or_type, name=name, name_off=name_off,
                         btf=btf)

        loc = btf.buffpos + self.bufsize

        self.bufsize += BTFDECL_TAG_SIZE

        self.subname = "component_idx"

        (idx) = BTFDECL_TAG.unpack(btf.buff[loc:loc + BTFDECL_TAG_SIZE])
        self.subrecords.append(idx)

BASE_TYPES = [
    BTFGeneric(kind=BTFKIND_VOID, name="void"),
    BTFGeneric(kind=BTFKIND_INT, name="int"),
    BTFGeneric(kind=BTFKIND_PTR, name="ptr"),
    BTFGeneric(kind=BTFKIND_ARRAY, name="array"),
    BTFGeneric(kind=BTFKIND_STRUCT, name="struct"),
    BTFGeneric(kind=BTFKIND_ENUM, name="enum"),
    BTFGeneric(kind=BTFKIND_FWD, name="fwd"),
    BTFGeneric(kind=BTFKIND_TYPEDEF, name="typedef"),
    BTFGeneric(kind=BTFKIND_VOLATILE, name="volatile"),
    BTFGeneric(kind=BTFKIND_CONST, name="const"),
    BTFGeneric(kind=BTFKIND_RESTRICT, name="restrict"),
    BTFGeneric(kind=BTFKIND_FUNC, name="func"),
    BTFGeneric(kind=BTFKIND_FUNC_PROTO, name="func_proto"),
    BTFGeneric(kind=BTFKIND_VAR, name="var"),
    BTFGeneric(kind=BTFKIND_DATASEC, name="datasec"),
    BTFGeneric(kind=BTFKIND_FLOAT, name="float"),
    BTFGeneric(kind=BTFKIND_DECL_TAG, name="decl_tag"),
    BTFGeneric(kind=BTFKIND_TYPE_TAG, name="type_tag"),
    BTFGeneric(kind=BTFKIND_ENUM64, name="enum64")
]

JUMP_TABLE = {
    BTFKIND_ARRAY: BTFArray,
    BTFKIND_STRUCT: BTFStruct,
    BTFKIND_UNION: BTFStruct,
    BTFKIND_ENUM: BTFEnum,
    BTFKIND_FUNC_PROTO: BTFFuncProto,
    BTFKIND_VAR: BTFVar,
    BTFKIND_DATASEC: BTFDataSec,
    BTFKIND_DECL_TAG: BTFDeclTag,
}

class BTFBlob():
    '''A blob of BTF Data'''
    # pylint: disable=too-many-instance-attributes

    def __init__(self, buff):
        self.buff = buff
        (magic, version, flags, self.hdr_len, self.type_off,
         self.type_len, self.str_off, self.str_len) = \
            BTFHEADER.unpack(buff[0:BTFHEADER_SIZE])
        self.elements = []
        self.elements.extend(BASE_TYPES)
        self.buffpos = self.type_off + BTFHEADER_SIZE

    def resolve_str(self, index):
        '''Resolve string from string table'''
        res = None
        start = self.str_off + BTFHEADER_SIZE + index
        try:
            for pos in range(start, len(self.buff)):
                if self.buff[pos] == 0:
                    res = str(self.buff[start:pos])
                    break
        except IndexError:
            pass
        return res

    def resolve_type(self, index):
        '''Resolve type from type table'''
        return self.elements[index]

    def parse(self):
        '''Parse blob'''
        rec_id = 20
        while self.buffpos < self.type_off + self.type_len:
            (name_off, info, size_or_type) = \
                BTFTYPE.unpack(self.buff[self.buffpos:self.buffpos + BTFSIZE])
            vlen = info & 0xFFFF
            kind = (info & 0x0F000000) >> 24
            kind_flag = not (info & 0x10000000) == 0
            rec = None
            try:
                rec = JUMP_TABLE[kind](kind=kind,
                                       vlen=vlen,
                                       kind_flag=kind_flag,
                                       size_or_type=size_or_type,
                                       name_off=name_off,
                                       btf=self)
            except KeyError:
                rec = BTFGeneric(kind=kind,
                                 vlen=vlen,
                                 kind_flag=kind_flag,
                                 size_or_type=size_or_type,
                                 name_off=name_off,
                                 btf=self)
            self.elements.append(rec)
            self.buffpos += rec.bufsize
            rec_id += 1


        for item in self.elements[20:]:
            for member in item.subrecords:
                try:
                    member["type"] = self.elements[member["type"]]
                except KeyError:
                    pass
                except IndexError:
                    pass
            if not item.has_size:
                try:
                    item.type = self.elements[item.type]
                except IndexError:
                    pass

    def __repr__(self):
        '''Print BTF data'''
        ret = ""
        for item in self.elements:
            if item.tid != 0 and item.tid != BTFKIND_FUNC:
                ret += "{}\n".format(item)
        return ret
